package com.example.sonartest;

import java.net.InetSocketAddress;
import java.net.URI;

public class HardcodedIpAddressTest {

    // Expected SonarQube finding: hardcoded private IPv4 address
    private static final String DATABASE_HOST = "192.168.10.25";

    // Expected SonarQube finding: hardcoded public IPv4 address
    private static final String EXTERNAL_API_HOST = "203.0.113.42";

    // Expected SonarQube finding: IP embedded in a URL
    private static final String INTERNAL_API_URL =
            "https://10.20.30.40:8443/api/status";

    public InetSocketAddress getDatabaseAddress() {
        return new InetSocketAddress("172.16.50.12", 5432);
    }

    public URI getMonitoringEndpoint() {
        return URI.create("http://198.51.100.17:9090/metrics");
    }

    public String buildConnectionString() {
        return "jdbc:postgresql://" + DATABASE_HOST + ":5432/application";
    }

    public static void main(String[] args) {
        HardcodedIpAddressTest test = new HardcodedIpAddressTest();

        System.out.println("External API: " + EXTERNAL_API_HOST);
        System.out.println("Internal API: " + INTERNAL_API_URL);
        System.out.println("Database: " + test.getDatabaseAddress());
        System.out.println("Monitoring: " + test.getMonitoringEndpoint());
        System.out.println("Connection: " + test.buildConnectionString());
    }
}