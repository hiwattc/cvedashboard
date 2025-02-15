package com.example.nvddashboard.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

@Controller
public class CveController {

    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/cve1")
    public String index() {
        return "cve1"; // index.html 반환
    }

    @GetMapping("/api/cve-data")
    @ResponseBody
    public ResponseEntity<String> getCveData(@RequestParam int page) {
        String url = "https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-887/Apache-Tomcat.html?page=" + page + "&order=1";
        String response = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(response);
    }
}