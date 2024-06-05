package raverside.utils;

public final class Constants {

    // Base URL for API calls
    public static final String API_BASE_URL = "https://raverside-server.aymeric-daniel.com";

    // API Endpoints
    public static final String API_USER_ENDPOINT = "users/";
    public static final String API_ANALYSIS_ENDPOINT = "analysis/";
    public static final String API_CHATBOT_ENDPOINT = "chatbot/";

    public static final String API_TMP_KEY = "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";



    // HTTP Methods
    public static final String HTTP_GET = "GET";
    public static final String HTTP_POST = "POST";

    // HTTP Headers
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_ACCEPT_JSON = "application/json";
    public static final String HEADER_CONTENT_TYPE_JSON = "application/json";

    // Error messages
    public static final String ERROR_NETWORK = "Network error";
    public static final String ERROR_API_REQUEST_FAILED = "API request failed with response code ";
    public static final String ERROR_INVALID_RESPONSE = "Invalid response from API";
    public static final String ERROR_USER_NOT_FOUND = "User not found";

    // Success messages
    public static final String SUCCESS_ANALYSIS_COMPLETE = "Analysis completed successfully";
    public static final String SUCCESS_VARIABLE_RENAMED = "Variable renamed successfully";
    public static final String SUCCESS_CHATBOT_RESPONSE = "Chatbot response received successfully";

    // Other constants
    public static final int TIMEOUT_SECONDS = 30;
    public static final int MAX_RETRIES = 3;

    // Prevent instantiation
    private Constants() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}
