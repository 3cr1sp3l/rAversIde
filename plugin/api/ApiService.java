package raverside.api;

import com.google.gson.JsonObject;

import java.io.IOException;

public class ApiService {
    public boolean clearChatHistoryRequest(String apiKey) {
        JsonObject requestData = new JsonObject();
        try {
            requestData.addProperty("apiKey", apiKey);
            ApiClient.sendPostRequest("/clear", requestData.toString());
        } catch (IOException ex) {
            throw new RuntimeException("Failed to clear chat history", ex);
        }
        return true;
    }

//    public void renameVariableAndFunction(String selectedFunctionName, String[] selectedVariableNames, String apiKey) throws IOException {
//        ConsoleService consoleService = tool.getService(ConsoleService.class);
//        Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
//
//        if (selectedFunction != null) {
////            consoleService.addMessage("selectedFunctionName :", selectedFunctionName + "\n");
//            apiManager.sendRenameVariableAndFunctionRequest(selectedFunctionName, selectedVariableNames, apiKey, responseJson -> {
////                consoleService.addMessage("response :", responseJson + "\n");
//                consoleService.addMessage("Rename", "Received\n");
//                if (responseJson != null) {
//                    processRenameResponse(responseJson, selectedFunction);
////                    consoleService.addMessage("response :", responseJson + "\n");
//                }
//            }, error -> {
//                consoleService.addErrorMessage("API Error", "Error while renaming function: " + error.getMessage());
//            });
//        }
//    }


}
