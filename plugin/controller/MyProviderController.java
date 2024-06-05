package raverside.controller;

import com.google.gson.JsonObject;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.configuration2.interpol.ExprLookup;
import raverside.RaversidePlugin;
import raverside.api.ApiClient;
import raverside.api.ApiService;
import raverside.utils.Helper;
import raverside.view.MyProviderPanel;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static raverside.utils.Helper.isFunctionPartOfExecutable;

public class MyProviderController {
    private final ApiManager apiManager;
    private final FeatureManager featureManager;
    private final MyProviderPanel view;
    private Program program;
    private final PluginTool tool;
    private final Helper helper;
    private boolean isCodeSendEnabled;
    private ApiService apiService;

    public MyProviderController(RaversidePlugin plugin) {
        this.tool = plugin.getTool();
        this.featureManager = plugin.getFeatureManager();
        this.helper = plugin.getHelper();
        this.apiManager = plugin.getApiManager();
        this.view = plugin.getPanel();
        this.apiService = new ApiService();

        this.view.analysePatternsButton.addActionListener(e -> { analysePatterns();});
        this.view.functionComboBox.addItemListener(e -> onFunctionSelected());
        this.view.questionArea.addKeyListener(new KeyAdapter() {
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    sendQuestion();
                }
            }
        });
        this.view.sendButton.addActionListener(e -> sendQuestion());
        this.view.clearButton.addActionListener(e -> {
            apiService.clearChatHistoryRequest(apiManager.getApiKey()); view.textArea.setText("");
            helper.printOutput("Chat history cleared\n");
        });
        this.view.renameVariablesButton.addActionListener(e -> renameTask());
        this.view.searchField.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                searchFunction();
            }
        });


    }
    public void searchFunction(){
        String searchText = view.searchField.getText().toLowerCase();
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();

        String[] functionNames = Helper.retrieveFunctionNames();
        assert functionNames != null;
        for (String function : functionNames) {
            if (function.toLowerCase().contains(searchText)) {
                model.addElement(function);
            }
        }

        view.functionComboBox.setModel(model);
    }

    public void setProgram(Program p) {
        this.program = p;
        this.featureManager.setProgram(p);
        this.apiManager.setProgram(p);
        this.helper.setProgram(p);
    }

    public void refresh() {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        setProgram(programManager.getCurrentProgram());

        view.functionComboBox.removeAllItems();

        view.functionComboBox.addItem("All Functions");
        view.functionComboBox.addItem("Multiple Functions");

        FunctionIterator functionIterator = program.getListing().getFunctions(true);
        List<Function> functions = new ArrayList<>();
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (isFunctionPartOfExecutable(function)) {
                functions.add(function);
            }
        }

        Collections.sort(functions, (a, b) -> a.getName().compareTo(b.getName()));
        functions.forEach(f -> view.functionComboBox.addItem(f.getName()));

        view.functionComboBox.setSelectedIndex(0);
    }

    public void renameVariableAndFunction(String selectedFunctionName, String[] selectedVariableNames) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
        if (selectedFunction != null) {
//            consoleService.addMessage("selectedFunctionName :", selectedFunctionName + "\n");
            apiManager.sendRenameVariableAndFunctionRequest(selectedFunctionName, selectedVariableNames,responseJson -> {
//                consoleService.addMessage("response :", responseJson + "\n");
                consoleService.addMessage("Rename", "Received\n");
                if (responseJson != null) {
                    featureManager.processRenameResponse(responseJson, selectedFunction);
//                    consoleService.addMessage("response :", responseJson + "\n");
                }
            });
        }
    }

    void renameTask() {

        String apiKey = view.apiTextField.getText();
        apiManager.setApiKey(apiKey);
        String selectedFunctionName = (String) view.functionComboBox.getSelectedItem();
        if ("All Functions".equals(selectedFunctionName)) {
            JOptionPane.showMessageDialog(null, "All Functions cannot be selected for rename", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (selectedFunctionName.equals("Multiple Functions")) {
            List<String> functionsToRename = featureManager.createAnalysisFunctionSelector();
            for (String functionName : functionsToRename) {
                Function selectedFunction = Helper.getFunctionByName(functionName, program);
                assert selectedFunction != null;
                Variable[] variables = selectedFunction.getAllVariables();

                String[] variableNames = Arrays.stream(variables)
                        .map(Variable::getName)
                        .toArray(String[]::new);

                renameVariableAndFunction(functionName, variableNames);
            }
            return;
        }
        Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
        assert selectedFunction != null;
        Variable[] variables = selectedFunction.getAllVariables();

        String[] variableNames = Arrays.stream(variables)
                .map(Variable::getName)
                .toArray(String[]::new);

        renameVariableAndFunction(selectedFunctionName, variableNames);
        refresh();
    }

    private void analysePatterns() {


        ConsoleService consoleService = tool.getService(ConsoleService.class);
        String apiKey = view.apiTextField.getText();
        apiManager.setApiKey(apiKey);

        String selectedFunctionName = (String) view.functionComboBox.getSelectedItem();

        ProgramManager programManager = tool.getService(ProgramManager.class);
        Program currentProgram = programManager.getCurrentProgram();
        boolean getAllCode = "All Functions".equals(selectedFunctionName);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Listing listing = currentProgram.getListing();
        JsonObject request = null;

        List<String> functionsNames = new ArrayList<>();

        if ("Multiple Functions".equals(selectedFunctionName)) {

//        Get functions names and decompiled code
            functionsNames = featureManager.createAnalysisFunctionSelector();
            request = helper.prepareAnalysisRequestForMultipleFunctions(decomp, listing, functionsNames);
        }
        else if ("All Functions".equals(selectedFunctionName)) {
            functionsNames = new ArrayList<>();
            for (Function function : listing.getFunctions(true)) {
                if (isFunctionPartOfExecutable(function)) {
                    functionsNames.add(function.getName());
                }
            }
            request = helper.prepareAnalysisRequest(program, decomp, getAllCode, view.functionComboBox);
        }
        else {
            functionsNames = new ArrayList<>(Collections.singletonList(selectedFunctionName));
            request = helper.prepareAnalysisRequest(program, decomp, getAllCode, view.functionComboBox);
        }
        request.addProperty("rag", true);
        if (view.apiTextField.getText().equals("Enter your Hugging Face API key...")) {
            consoleService.addMessage("API Key", "Please enter your Hugging Face API key");
            return;
        }
        request.addProperty("apiKey", apiKey);

        List<String> finalFunctionsNames = functionsNames;
        apiManager.sendAnalysisRequest(request, responseJson -> {
            if (responseJson != null) {
                featureManager.processAnalysisResponse(currentProgram, responseJson, finalFunctionsNames);
                consoleService.addMessage("response :", responseJson + "\n");
            }
            refresh();;
        });
    }

    private void onFunctionSelected() {
        String functionName = (String) view.functionComboBox.getSelectedItem();
        if (functionName == null) {
            return;
        }

        Function function = Helper.getFunctionByName(functionName, program);
    }

    private void sendQuestion() {
        String apiKey = view.apiTextField.getText();
        apiManager.setApiKey(apiKey);
        if (view.textArea.getText().trim().isEmpty()) {
            apiService.clearChatHistoryRequest(apiManager.getApiKey());
            helper.printOutput("Chat history cleared\n");
        }

        String question = view.questionArea.getText();
        if (question.trim().isEmpty()) {
            return;
        }
        helper.printOutput("User :\n"+question+"\n");
        view.resetQuestionArea();

        apiManager.sendChatBotRequest(question, e -> helper.printOutputChatbot(e), view.functionComboBox.getSelectedItem().toString(), view.isSendCodeEnabled());
    }
}
