package com.example.nvddashboard.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.text.SimpleDateFormat;
import java.util.*;

@Controller
public class DashboardController {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping("/dashboard")
    public String getDashboard(Model model, @RequestParam(required = false, defaultValue = "") String keywordSearch ) {
        String apiUrl = buildApiUrl(keywordSearch);
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(apiUrl, String.class);
            JsonNode root = objectMapper.readTree(response.getBody());
            List<Map<String, Object>> vulnerabilities = new ArrayList<>();
            Map<String, List<Map<String, Object>>> dailyVulnerabilities = new HashMap<>();

            if (root.has("vulnerabilities") && root.get("vulnerabilities").isArray()) {
                for (JsonNode vuln : root.get("vulnerabilities")) {
                    if (vuln.has("cve")) {
                        JsonNode cve = vuln.get("cve");
                        String id = cve.has("id") ? cve.get("id").asText() : "Unknown";
                        
                        // Get description
                        String description = "No description available";
                        if (cve.has("descriptions") && cve.get("descriptions").isArray() && 
                            cve.get("descriptions").size() > 0 && 
                            cve.get("descriptions").get(0).has("value")) {
                            description = cve.get("descriptions").get(0).get("value").asText();
                        }
                        
                        // Get published date
                        String published = "Unknown";
                        if (cve.has("published")) {
                            published = cve.get("published").asText();
                        }
                        
                        // Extract date part only (yyyy-MM-dd)
                        String dateOnly = published.length() >= 10 ? published.substring(0, 10) : null;
                        if (dateOnly == null) {
                            continue; // Skip this vulnerability if no valid date
                        }
                        
                        // Get CVSS score if available
                        double cvssScore = 0.0;
                        if (cve.has("metrics")) {
                            JsonNode metrics = cve.get("metrics");
                            if (metrics.has("cvssMetricV31") && metrics.get("cvssMetricV31").isArray() && 
                                metrics.get("cvssMetricV31").size() > 0) {
                                JsonNode cvssMetric = metrics.get("cvssMetricV31").get(0);
                                if (cvssMetric.has("cvssData") && cvssMetric.get("cvssData").has("baseScore")) {
                                    cvssScore = cvssMetric.get("cvssData").get("baseScore").asDouble();
                                }
                            } else if (metrics.has("cvssMetricV30") && metrics.get("cvssMetricV30").isArray() && 
                                      metrics.get("cvssMetricV30").size() > 0) {
                                JsonNode cvssMetric = metrics.get("cvssMetricV30").get(0);
                                if (cvssMetric.has("cvssData") && cvssMetric.get("cvssData").has("baseScore")) {
                                    cvssScore = cvssMetric.get("cvssData").get("baseScore").asDouble();
                                }
                            } else if (metrics.has("cvssMetricV2") && metrics.get("cvssMetricV2").isArray() && 
                                      metrics.get("cvssMetricV2").size() > 0) {
                                JsonNode cvssMetric = metrics.get("cvssMetricV2").get(0);
                                if (cvssMetric.has("cvssData") && cvssMetric.get("cvssData").has("baseScore")) {
                                    cvssScore = cvssMetric.get("cvssData").get("baseScore").asDouble();
                                }
                            }
                        }
                        
                        Map<String, Object> vulnData = new HashMap<>();
                        vulnData.put("id", id);
                        vulnData.put("description", description);
                        vulnData.put("published", published);
                        vulnData.put("cvssScore", cvssScore);
                        
                        vulnerabilities.add(vulnData);
                        
                        // Group by date for calendar
                        if (!dailyVulnerabilities.containsKey(dateOnly)) {
                            dailyVulnerabilities.put(dateOnly, new ArrayList<>());
                        }
                        dailyVulnerabilities.get(dateOnly).add(vulnData);
                    }
                }
            }

            // Prepare calendar data for ECharts
            List<List<Object>> calendarData = new ArrayList<>();
            int maxCount = 0;
            double maxCvss = 0.0;
            
            for (Map.Entry<String, List<Map<String, Object>>> entry : dailyVulnerabilities.entrySet()) {
                String date = entry.getKey();
                List<Map<String, Object>> dateVulns = entry.getValue();
                int count = dateVulns.size();
                
                if (count > maxCount) {
                    maxCount = count;
                }
                
                // Calculate highest CVSS score for tooltip
                List<String> cveList = new ArrayList<>();
                
                for (Map<String, Object> vuln : dateVulns) {
                    double score = (double) vuln.get("cvssScore");
                    if (score > maxCvss) {
                        maxCvss = score;
                    }
                    cveList.add((String) vuln.get("id"));
                }
                
                // Create data point for ECharts [date, count, maxCvss, cveList]
                List<Object> dataPoint = new ArrayList<>();
                dataPoint.add(date);
                dataPoint.add(maxCvss);
                //dataPoint.add(count);
                /*
                if (!cveList.isEmpty()) {
                    // Limit the number of CVEs shown in tooltip to prevent it from being too large
                    if (cveList.size() > 5) {
                        List<String> limitedList = new ArrayList<>(cveList.subList(0, 5));
                        limitedList.add("... and " + (cveList.size() - 5) + " more");
                        dataPoint.add(limitedList);
                    } else {
                        dataPoint.add(cveList);
                    }
                } else {
                    dataPoint.add(null);
                } */
                
                calendarData.add(dataPoint);
            }

            // Debug logs
            System.out.println("Total vulnerabilities: " + vulnerabilities.size());
            System.out.println("Unique dates: " + dailyVulnerabilities.size());
            System.out.println("Calendar data points: " + calendarData.size());
            System.out.println("Max count: " + maxCount);

            model.addAttribute("vulnerabilities", vulnerabilities);
            model.addAttribute("vulnerabilityData", calendarData);
            model.addAttribute("maxCount", maxCount);
            model.addAttribute("maxCvss", maxCvss);
            
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Failed to fetch data from NVD API: " + e.getMessage());
        }

        return "dashboard";
    }

    private String buildApiUrl(String keywordSearch) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Calendar calendar = Calendar.getInstance();

        // The maximum allowable range when using any date range parameters is 120 consecutive days.
        calendar.add(Calendar.DATE, -119);
        String startDate = sdf.format(calendar.getTime());
        String endDate = sdf.format(new Date());

        if(!"".equals(keywordSearch)){
            return "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" + startDate + "T00:00:00.000Z&pubEndDate=" + endDate + "T23:59:59.000Z&keywordSearch="+keywordSearch;
        }else{
            return "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" + startDate + "T00:00:00.000Z&pubEndDate=" + endDate + "T23:59:59.000Z&keywordSearch=tomcat";
            //return "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" + startDate + "T00:00:00.000Z&pubEndDate=" + endDate + "T23:59:59.000Z&keyword=apache%20tomcat,apache%20httpd&resultsPerPage=100";
        }
    }
}