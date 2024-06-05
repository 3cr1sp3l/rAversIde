package raverside.controller;


import com.google.gson.JsonObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.app.services.ConsoleService;
import raverside.MyProvider;
import raverside.RaversidePlugin;
import raverside.api.ApiClient;
import raverside.utils.Helper;

import javax.swing.*;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

public class ApiManager {

    private final PluginTool tool;
    private Program program;
    private final ReentrantLock lock = new ReentrantLock();
    private String apiKey;
    private Helper helper;

    public ApiManager(RaversidePlugin plugin) {
        this.tool = plugin.getTool();
        this.program = plugin.getCurrentProgram();
        this.helper = plugin.getHelper();
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public void sendRenameVariableAndFunctionRequest(String selectedFunctionName, String[] selectedVariableName, Consumer<String> callback) {
        TaskMonitor monitor = tool.getService(TaskMonitor.class);

        JsonObject request = null;
        try {
            request = Helper.createRenameVariableAndFunctionRequestJson(selectedVariableName, selectedFunctionName, program, monitor);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        ConsoleService consoleService = tool.getService(ConsoleService.class);
        if (!isApiKeyValid()){
        return;
        }
        request.addProperty("apiKey", apiKey);
        consoleService.addMessage("a request is in progress  :", "RenameVariableAndFunction " + request);

        ApiClient.sendPostRequestAsync("/renameVariableAndFunction", request.toString(), callback);
        consoleService.addMessage("message sent :", "OK");
    }

    public void sendChatBotRequest(String question, Consumer<String> callback, String selectedFunctionName, Boolean isCodeSendEnabled) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);

        consoleService.addMessage("selectedFunctionName", selectedFunctionName);
        consoleService.addMessage("isCodeSendEnabled", isCodeSendEnabled.toString());
        JsonObject request = helper.createChatBotRequest(question, program, tool, selectedFunctionName, isCodeSendEnabled);

        consoleService.addMessage("a request is in progress  :", "ChatBot " + request);

        if (!isApiKeyValid()){
            return;
        }
        request.addProperty("apiKey", apiKey);
        ApiClient.sendPostRequestAsync("/chatbot", request.toString(), callback);

        consoleService.addMessage("message sent :", "OK");
    }

    public void sendAnalysisRequest(JsonObject request, Consumer<String> callback) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);

        if (!isApiKeyValid()){
            return;
        }

        request.addProperty("apiKey", apiKey);
        ApiClient.sendPostRequestAsync("/analyze", request.toString(), callback);

        consoleService.addMessage("message sent :", "OK");
    }


    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void showErrorApiKeyNotSet() {
        JOptionPane.showMessageDialog(null, "API key is not set", "Error", JOptionPane.ERROR_MESSAGE);
    }

    public boolean isApiKeyValid() {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        if (apiKey == null || apiKey.isEmpty() || !apiKey.startsWith("hf_")){
            showErrorApiKeyNotSet();
            consoleService.addMessage("API key is not set", "Please set the API key in the settings");
            return false;
        }
        return true;
    }
}
