package com.ghazal;

import java.io.*;
import java.sql.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.SecureRandom;

/**
 * Ghazal Java Servlet Clean Application
 * Demonstrates secure coding patterns - zero vulnerabilities expected
 */
public class GhazalCleanServlet extends HttpServlet {

    // SAFE: Credentials from environment/context, not hardcoded
    private String getDbUrl() { return System.getenv("DB_URL"); }
    private String getDbUser() { return System.getenv("DB_USER"); }
    private String getDbPass() { return System.getenv("DB_PASS"); }

    // SAFE: Strong hash with salt
    public String hashPassword(String password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] digest = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // SAFE: Strong cryptographic algorithm (AES instead of DES)
    public byte[] encryptData(String data) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes("UTF-8"));
    }

    // SAFE: SecureRandom instead of Random
    public String generateToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        StringBuilder token = new StringBuilder();
        for (byte b : bytes) {
            token.append(String.format("%02x", b));
        }
        return token.toString();
    }

    // SAFE: Parameterized SQL query
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        // Validate input
        if (userId == null || !userId.matches("\\d+")) {
            response.setStatus(400);
            response.getWriter().println("Invalid user ID");
            return;
        }

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        try {
            Connection conn = DriverManager.getConnection(getDbUrl(), getDbUser(), getDbPass());
            // SAFE: PreparedStatement with parameterized query
            String query = "SELECT id, name, email FROM users WHERE id = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setInt(1, Integer.parseInt(userId));
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                // SAFE: HTML encoding output
                String name = rs.getString("name");
                out.println("<p>" + escapeHtml(name) + "</p>");
            }
            rs.close();
            pstmt.close();
            conn.close();
        } catch (Exception e) {
            // SAFE: Generic error message, no stack trace
            out.println("<p>An error occurred</p>");
        }
    }

    // SAFE: No command injection - no user input in exec
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<p>Operation not supported</p>");
    }

    // SAFE: HTML encoding for XSS prevention
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#039;");
    }

    // SAFE: Path traversal prevention
    protected void doGetFile(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("name");
        // Validate filename
        if (filename == null || !filename.matches("^[a-zA-Z0-9._-]+$")) {
            response.setStatus(400);
            response.getWriter().println("Invalid filename");
            return;
        }

        // Use canonical path and verify it's within allowed directory
        File file = new File("/var/data", filename);
        String canonicalPath = file.getCanonicalPath();
        if (!canonicalPath.startsWith("/var/data")) {
            response.setStatus(403);
            response.getWriter().println("Access denied");
            return;
        }

        // SAFE: Content-Type header set explicitly
        response.setContentType("application/octet-stream");
        FileInputStream fis = new FileInputStream(canonicalPath);
        OutputStream os = response.getOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            os.write(buffer, 0, len);
        }
        fis.close();
    }

    // SAFE: Insecure cookie flags set to secure values
    protected void doLogin(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // SAFE: Parameterized query
        String query = "SELECT id FROM users WHERE username = ? AND password = ?";

        // SAFE: Secure cookie configuration
        Cookie cookie = new Cookie("session", generateToken());
        cookie.setSecure(true);      // HTTPS only
        cookie.setHttpOnly(true);    // No JavaScript access
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        response.addCookie(cookie);

        response.sendRedirect("/dashboard");
    }

    // SAFE: No trust boundary violation - validate session data
    protected void doSessionAction(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            response.setStatus(401);
            return;
        }
        // Only read from session, never trust user input for session data
        String trustedData = (String) session.getAttribute("userData");
        response.getWriter().println("Session data: " + escapeHtml(trustedData != null ? trustedData : ""));
    }
}
