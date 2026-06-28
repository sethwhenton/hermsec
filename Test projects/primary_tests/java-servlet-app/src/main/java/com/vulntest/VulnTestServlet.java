package com.vulntest;

import java.io.*;
import java.sql.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Random;

/**
 * VulnTest Java Servlet Vulnerable Application
 * Deliberately vulnerable for Hermsec benchmark testing
 */
public class VulnTestServlet extends HttpServlet {

    // VULN 1: Hardcoded database credentials (CWE-798)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/vulntest_db";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "admin123!@#";

    // VULN 2: Hardcoded API key (CWE-798)
    private static final String API_KEY = "vulntest-java-api-key-12345678";

    // VULN 3: Weak hash - MD5 (CWE-328)
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // VULN 4: Weak cryptographic algorithm - DES (CWE-327)
    public byte[] encryptData(String data) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULN 5: Weak random (CWE-330)
    public String generateToken() {
        Random random = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append((char) ('a' + random.nextInt(26)));
        }
        return token.toString();
    }

    // VULN 6: SQL Injection via string concatenation (CWE-89)
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            // VULN: SQL Injection
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                out.println("<p>" + rs.getString("name") + "</p>");
            }
            conn.close();
        } catch (Exception e) {
            // VULN 7: Verbose error exposure (CWE-209)
            out.println("<pre>" + e.getMessage() + "\n" + e.toString() + "</pre>");
        }
    }

    // VULN 8: Command Injection (CWE-78)
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        try {
            // VULN: Command Injection
            Process proc = Runtime.getRuntime().exec("ping -c 4 " + host);
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }

    // VULN 9: XSS - unsanitized output (CWE-79)
    protected void doSearch(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String query = request.getParameter("q");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        // VULN: XSS - user input reflected without sanitization
        out.println("<html><body><h1>Search results for: " + query + "</h1></body></html>");
    }

    // VULN 10: Path Traversal (CWE-22)
    protected void doGetFile(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("name");
        // VULN: Path Traversal
        String filepath = "/var/data/" + filename;
        FileInputStream fis = new FileInputStream(filepath);
        OutputStream os = response.getOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            os.write(buffer, 0, len);
        }
        fis.close();
    }

    // VULN 11: LDAP Injection (CWE-90)
    protected void doLdapSearch(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        try {
            // VULN: LDAP Injection
            String searchFilter = "(&(uid=" + username + ")(userPassword=*))";
            out.println("<p>LDAP search: " + searchFilter + "</p>");
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }

    // VULN 12: XPath Injection (CWE-643)
    protected void doXmlSearch(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("userid");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // VULN: XPath Injection
        String xpath = "//user[id='" + userId + "']";
        out.println("<p>XPath query: " + xpath + "</p>");
    }

    // VULN 13: Insecure cookie (CWE-614)
    protected void doLogin(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // VULN: SQL Injection in login
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";

        Cookie cookie = new Cookie("session", generateToken());
        // VULN: Cookie without Secure flag, without HttpOnly
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);

        response.sendRedirect("/dashboard");
    }

    // VULN 14: Trust boundary violation (CWE-501)
    protected void doSessionAction(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession();
        // VULN: User-controlled data stored in session
        String userData = request.getParameter("userdata");
        session.setAttribute("trustedData", userData);

        // VULN: Reading back untrusted data from session
        String trusted = (String) session.getAttribute("trustedData");
        response.getWriter().println("Session data: " + trusted);
    }

    // VULN 15: Process injection with user-controlled array (CWE-78)
    protected void doProcessExec(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String[] commands = request.getParameterValues("cmd");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        try {
            // VULN: Executing user-controlled command array
            Process proc = Runtime.getRuntime().exec(commands);
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }

    // VULN 16: Deserialization of untrusted data (CWE-502)
    protected void doObjectLoad(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        try {
            // VULN: Deserializing untrusted data
            Object obj = ois.readObject();
            response.getWriter().println("Loaded: " + obj.toString());
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    // VULN 17: Hardcoded JWT secret (CWE-798)
    private static final String JWT_SECRET = "vulntest-java-jwt-secret-2024";

    // VULN 18: SSRF (CWE-918)
    protected void doProxy(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String url = request.getParameter("url");
        // VULN: SSRF - fetching user-controlled URL
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
        InputStream is = conn.getInputStream();
        byte[] data = is.readAllBytes();
        response.getOutputStream().write(data);
    }

    // VULN 19: XXE (CWE-611)
    protected void doXmlParse(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // VULN: XXE - no disabling of external entities
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc = db.parse(request.getInputStream());
        response.getWriter().println("Parsed XML: " + doc.getDocumentElement().getNodeName());
    }

    // VULN 20: Open redirect (CWE-601)
    protected void doRedirect(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String url = request.getParameter("url");
        // VULN: Open redirect
        response.sendRedirect(url);
    }
}
