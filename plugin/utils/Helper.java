package raverside.utils;


import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;
import raverside.RaversidePlugin;
import raverside.controller.FeatureManager;
import raverside.controller.MyProviderController;
import raverside.view.MyProviderPanel;

import javax.swing.*;
import java.io.IOException;
import java.util.*;

public class Helper {

    private static PluginTool tool;
    private Program program;
    private FeatureManager featureManager;
    private MyProviderPanel panel;
    private MyProviderController controller;
    private RaversidePlugin plugin;

    public Helper(RaversidePlugin plugin) {
        Helper.tool = plugin.getTool();
        this.program = plugin.getCurrentProgram();
        this.featureManager = plugin.getFeatureManager();
        this.panel = plugin.getPanel();
        this.controller = plugin.getProviderControler();

        this.plugin = plugin;
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public static JsonObject createRenameFunctionRequestJson(String functionName, Program program, TaskMonitor monitor, String apiKey) throws IOException {
        Function function = getFunctionByName(functionName, program);
        if (function == null) {
            throw new IOException("Function not found: " + functionName);
        }

        return buildJsonRequest(function, "fonction", functionName, program, monitor, apiKey);
    }

    public static JsonObject createRenameVariableRequestJson(String variableName, String functionName, Program program, TaskMonitor monitor, String apiKey) throws IOException {
        Function function = getFunctionByName(functionName, program);
        if (function == null) {
            throw new IOException("Function not found: " + functionName);
        }

        Variable variable = getVariableByName(variableName, function);
        if (variable == null) {
            throw new IOException("Variable not found: " + variableName);
        }

        return buildJsonRequest(function, "variable", variableName, program, monitor, apiKey);
    }

    public static JsonObject createRenameVariableAndFunctionRequestJson(String[] variablesNames, String functionName, Program program, TaskMonitor monitor) throws IOException {
        Function function = getFunctionByName(functionName, program);
        if (function == null) {
            throw new IOException("Function not found: " + functionName);
        }

        JsonObject request = new JsonObject();
        JsonArray itemsArray = new JsonArray();

        for (String variableName : variablesNames) {
            Variable variable = getVariableByName(variableName, function);
            if (variable == null) {
                throw new IOException("Variable not found: " + variableName);
            }

            JsonObject renameItem = new JsonObject();
            renameItem.addProperty("item_type", "variable");
            renameItem.addProperty("old_name", variableName);
            itemsArray.add(renameItem);
        }

        JsonObject renameItem = new JsonObject();
        renameItem.addProperty("item_type", "function");
        renameItem.addProperty("old_name", functionName);
        itemsArray.add(renameItem);

        request.add("items", itemsArray);
        addFunctionCodeToJson(request, function, program, monitor);

        return request;
    }

    private static JsonObject buildJsonRequest(Function function, String itemType, String oldName, Program program, TaskMonitor monitor, String apiKey) {
        JsonObject request = new JsonObject();
        JsonArray itemsArray = new JsonArray();
        JsonObject renameItem = new JsonObject();
        renameItem.addProperty("item_type", itemType);
        renameItem.addProperty("old_name", oldName);
        itemsArray.add(renameItem);

        request.add("items", itemsArray);
        addFunctionCodeToJson(request, function, program, monitor);

        request.addProperty("apiKey", apiKey);
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("request :", String.valueOf(request));

        return request;
    }

    private static void addFunctionCodeToJson(JsonObject request, Function function, Program program, TaskMonitor monitor) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        JsonObject code_c = new JsonObject();
        code_c.addProperty(function.getName(), decomp.decompileFunction(function, 0, monitor).getDecompiledFunction().getC());

        request.add("code_c", code_c);
    }

    public static Function getFunctionByName(String functionName, Program program) {
        Listing listing = program.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        for (Function function : functions) {
            if (function.getName().equals(functionName)) {
                return function;
            }
        }
        return null;
    }

    public static Variable getVariableByName(String variableName, Function functionContext) {
        if (functionContext != null) {
            for (Variable variable : functionContext.getAllVariables()) {
                if (variable.getName().equals(variableName)) {
                    return variable;
                }
            }
        }
        return null;
    }

    public JsonObject createChatBotRequest(String question, Program program, PluginTool tool, String selectedFunctionName, boolean isCodeSendEnabled) {
//        controller.refresh();
        refreshVariables();

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        TaskMonitor monitor = tool.getService(TaskMonitor.class);

        JsonObject request = new JsonObject();
        request.addProperty("action", "Chatbot");
        request.addProperty("question", question);

        if (isCodeSendEnabled) {
            JsonObject code_c = new JsonObject();

            Listing listing = program.getListing();
            FunctionIterator functions = listing.getFunctions(true);

            for (Function function : functions) {
                if (selectedFunctionName.equals("All Functions") && isFunctionPartOfExecutable(function)) {
                    code_c.addProperty(function.getName(), decomp.decompileFunction(function, 0, monitor).getDecompiledFunction().getC());
                } else if (function.getName().equals(selectedFunctionName)) {
                    code_c.addProperty(function.getName(), decomp.decompileFunction(function, 0, monitor).getDecompiledFunction().getC());
                }
            }

            request.add("code_c", code_c);
        }


        return request;
    }

    public JsonObject prepareAnalysisRequest(Program program, DecompInterface decomp, boolean getAllCode, JComboBox<String> functionComboBox) {
        JsonObject request = new JsonObject();
        request.addProperty("action", "Analyse");

        JsonObject code_c = new JsonObject();

        Listing listing = program.getListing();
        FunctionIterator functions = listing.getFunctions(true);

        while (functions.hasNext()) {
            Function function = functions.next();
            if ((getAllCode && isFunctionPartOfExecutable(function))|| function.getName().equals(functionComboBox.getSelectedItem())) {
                featureManager.addFunctionCodeToRequest(function, listing, decomp, code_c);
            }
        }

        request.add("code_c", code_c);
        return request;
    }

    public JsonObject prepareAnalysisRequestForMultipleFunctions(DecompInterface decomp, Listing listing, List<String> functionsNames) {
        JsonObject request = new JsonObject();
        request.addProperty("action", "Analyse");
        request.addProperty("type", "vulnérabilité");

        JsonObject code_c = new JsonObject();

        FunctionIterator functionIterator = listing.getFunctions(true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (functionsNames.contains(function.getName())) {
                featureManager.addFunctionCodeToRequest(function, listing, decomp, code_c);

            }
        }

        request.add("code_c", code_c);
        return request;
    }

    public static boolean isFunctionPartOfExecutable(Function function) {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        Program currentProgram = programManager.getCurrentProgram();

        Symbol functionSymbol = function.getSymbol();
        if (functionSymbol == null || functionSymbol.isExternal()) {
            return false;
        }

        // Liste des fonctions à exclure
        List<String> excludedFunctions = Arrays.asList(
                "_init", "_start", "_fini", "frame_dummy",
                "mainCRTStartup", "__libc_csu_init", "__libc_csu_fini", "_exit",
                "__do_global_dtors_aux", "deregister_tm_clones", "register_tm_clones"
        );

        // Obtenez le nom de la fonction et vérifiez si elle est dans la liste des exclusions
        String functionName = function.getName();
        if (excludedFunctions.contains(functionName)) {
            return false;
        }

        // Vérifiez si la fonction appartient à un espace de noms qui indique qu'elle est importée ou générée par Ghidra
        Namespace functionNamespace = functionSymbol.getParentNamespace();
        if (functionNamespace != null && (functionNamespace.isExternal() || functionNamespace.getName().equals("Imports"))) {
            return false;
        }

        // Analyse des instructions de la fonction
        InstructionIterator it = currentProgram.getListing().getInstructions(function.getBody(), true);
        if (it.hasNext()) {
            Instruction firstInstr = it.next();
            String firstMnemonic = firstInstr.getMnemonicString();

            // Vérifiez la séquence d'instructions
            if ((firstMnemonic.equals("PUSH") || firstMnemonic.equals("ENDBR64")) && it.hasNext()) {
                Instruction secondInstr = it.next();
                return !"JMP".equals(secondInstr.getMnemonicString()) && (!"RET".equals(secondInstr.getMnemonicString()) || it.hasNext());  // Exclure si la séquence correspond à PUSH/JMP ou ENDBR64/JMP ou ENDBR64/RET avec seulement deux instructions
            }
        }

        return true; // Inclure la fonction si aucune des conditions d'exclusion n'est remplie
    }

    public void printOutput(String string) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        panel.textArea.append(string+"\n");
        consoleService.addMessage("response :", string);
    }

    public void printOutputChatbot(String e) {
        Gson gson = new Gson();
        JsonObject jsonObject = gson.fromJson(e, JsonObject.class);
        printOutput("IA :\n"+jsonObject.get("answer").getAsString()+"\n\n");
    }

    private void refreshVariables() {
        this.program = plugin.getCurrentProgram();
        this.featureManager = plugin.getFeatureManager();
        this.panel = plugin.getPanel();
        this.controller = plugin.getProviderControler();
    }

    public static String[] retrieveFunctionNames(){
        ProgramManager programManager = tool.getService(ProgramManager.class);

        Program currentProgram = programManager.getCurrentProgram();

        if (currentProgram == null)
            return null;
        Listing listing = currentProgram.getListing();
        List<String> functionsNames = new ArrayList<>();

        FunctionIterator functionIterator = listing.getFunctions(true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (isFunctionPartOfExecutable(function))
                functionsNames.add(function.getName());
        }


        return functionsNames.toArray(new String[0]);
    }



}
