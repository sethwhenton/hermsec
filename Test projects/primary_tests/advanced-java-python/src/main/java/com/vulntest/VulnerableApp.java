package com.vulntest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

public class VulnerableApp {

    // VULN 1: Hardcoded database credentials (CWE-798)
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "vulntest_java_adv_db_pass!@#";

    // VULN 2: Weak crypto - DES algorithm (CWE-327)
    public static byte[] encryptDES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // VULN 3: Weak random for security (CWE-330)
    public static String generateToken() {
        Random random = new Random();
        int token = random.nextInt(1000000);
        return String.valueOf(token);
    }

    // VULN 4: Path traversal (CWE-22)
    public static String readFile(String filename) throws IOException {
        File file = new File("data/" + filename);
        Scanner scanner = new Scanner(file);
        StringBuilder content = new StringBuilder();
        while (scanner.hasNextLine()) {
            content.append(scanner.nextLine());
        }
        scanner.close();
        return content.toString();
    }

    // VULN 5: SQL Injection (CWE-89)
    public static String getUser(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return "Executed: " + query;
    }

    // VULN 6: Command Injection (CWE-78)
    public static String pingHost(String host) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
        Process process = pb.start();
        Scanner scanner = new Scanner(process.getInputStream()).useDelimiter("\\A");
        return scanner.hasNext() ? scanner.next() : "";
    }

    // VULN 7: XSS (CWE-79)
    public static String searchPage(String query) {
        return "<html><body><h1>Search: " + query + "</h1></body></html>";
    }

    // VULN 8: Information exposure (CWE-209)
    public static String handleError() {
        try {
            throw new RuntimeException("Something went wrong");
        } catch (Exception e) {
            return "Error: " + e.getMessage() + "\nStack: " + e.getStackTrace()[0].toString();
        }
    }

    // VULN 9: Hardcoded API key (CWE-798)
    private static final String API_KEY = "vulntest-java-adv-api-key-1234567890abcdef";

    // VULN 10: Insecure cookie (CWE-614)
    public static void setInsecureCookie(javax.servlet.http.HttpServletResponse response) {
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("session", "abc123");
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
    }

    // VULN 11: Weak hash MD5 (CWE-328)
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // VULN 12: LDAP Injection (CWE-90)
    public static String ldapSearch(String username) {
        String filter = "(&(objectClass=person)(uid=" + username + "))";
        return "LDAP Filter: " + filter;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("VulnTest Java Advanced App");
        System.out.println(getUser("1"));
        System.out.println(generateToken());
        System.out.println(handleError());
    }
}
