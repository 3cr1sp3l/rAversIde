package raverside.api;

import ghidra.app.services.ConsoleService;
import raverside.utils.Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public class ApiClient {
    private final static ExecutorService executorService = Executors.newFixedThreadPool(4);

    public static String sendPostRequest(String endpoint, String jsonData) throws IOException {
        URL url = new URL(Constants.API_BASE_URL + endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json; utf-8");
        connection.setDoOutput(true);

        try (OutputStream outputStream = connection.getOutputStream()) {
            byte[] inputBytes = jsonData.getBytes(StandardCharsets.UTF_8);
            outputStream.write(inputBytes, 0, inputBytes.length);
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            String responseLine;
            while ((responseLine = bufferedReader.readLine()) != null) {
                response.append(responseLine.trim());
            }
        } finally {
            connection.disconnect();
        }

        return response.toString();
    }



    public static void sendPostRequestAsync(String endpoint, String data, Consumer<String> callback) {
        CompletableFuture.runAsync(() -> {
            try {
                URL url = new URL(Constants.API_BASE_URL + endpoint);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod("POST");
                con.setRequestProperty("Content-Type", "application/json; utf-8");
                con.setDoOutput(true);
                con.getOutputStream().write(data.getBytes(StandardCharsets.UTF_8));

                StringBuilder response = new StringBuilder();
                try (var br = new BufferedReader(new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                    String responseLine;
                    while ((responseLine = br.readLine()) != null) {
                        response.append(responseLine.trim());
                    }
                }
                callback.accept(response.toString());
            } catch (IOException e) {
                e.printStackTrace();
                // Handle error
            }
        });
    }



}
