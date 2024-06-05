package raverside.controller;

import com.google.gson.JsonElement;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.configuration2.interpol.ExprLookup;
import raverside.RaversidePlugin;
import raverside.model.RenameItem;
import raverside.utils.Helper;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.*;

import static raverside.utils.Helper.isFunctionPartOfExecutable;

public class FeatureManager {
    public final ApiManager apiManager;
    private Program program;
    private final PluginTool tool;
    private final RaversidePlugin plugin;

    public FeatureManager(RaversidePlugin plugin) {
        this.apiManager = plugin.getApiManager();
        this.program = plugin.getCurrentProgram();
        this.tool = plugin.getTool();
        this.plugin = plugin;
    }

    public void setProgram(Program program) {
        this.program = program;
    }


    public void processRenameResponse(Object responseJson, Function functionContext) {

        List<RenameItem> itemsToRename = new ArrayList<>();
//        itemsToRename.add(new RenameItem(functionContext.getName(), "newName", "fonction", functionContext));
//        itemsToRename.add(new RenameItem("oldName", "newName", "variable", functionContext));

        JsonObject response = JsonParser.parseString(responseJson.toString()).getAsJsonObject();
        JsonArray renames = response.getAsJsonArray("rename");
        if (renames != null) {
            for (int i = 0; i < renames.size(); i++) {
                JsonArray rename = renames.get(i).getAsJsonArray();
                String type = rename.get(0).getAsString();
                String oldName = rename.get(1).getAsString();
                String newName = rename.get(2).getAsString();
                itemsToRename.add(new RenameItem(oldName, newName, type, functionContext));
            }
        }

        RenameController controller = new RenameController(null, itemsToRename);
        List<RenameItem> toRename = controller.showRenameDialog();
        if (toRename != null) {
            toRename.sort(Comparator.comparing(RenameItem::getOldName));
            renameSelected(toRename);
        }
    }

    public List<String> createAnalysisFunctionSelector() {
        List<String> functionsNames = new ArrayList<>();
        Listing listing = this.plugin.getCurrentProgram().getListing();

        FunctionIterator functionIterator = listing.getFunctions(true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (isFunctionPartOfExecutable(function)) {
                functionsNames.add(function.getName());
            }
        }


        FunctionsController controller = new FunctionsController(null, functionsNames);
        List<String> toAnalyse = controller.showFunctionsSelectorDialog();
        if (toAnalyse != null) {
            toAnalyse.sort(String::compareToIgnoreCase);
            return toAnalyse;
        }
        return null;
    }


    private void renameSelected(List<RenameItem> itemsToRename) {
        int transactionID = program.startTransaction("Rename Items");
        try {
            for (RenameItem item : itemsToRename) {
                if ("fonction".equals(item.getItemType())) {
                    Function function = Helper.getFunctionByName(item.getOldName(), program);
                    if (function != null) {
                        function.setName(item.getNewName(), SourceType.USER_DEFINED);
                    }
                } else if ("variable".equals(item.getItemType())) {
                    Variable variable = Helper.getVariableByName(item.getOldName(), item.getFunction());
                    if (variable != null) {
                        variable.setName(item.getNewName(), SourceType.USER_DEFINED);
                    }
                }
            }
            plugin.getProviderControler().refresh();
        } catch (Exception e) {
            Msg.showError(this, null, "Rename Error", "An error occurred during renaming: " + e.getMessage());
        } finally {
            program.endTransaction(transactionID, true);
        }
    }

    public void addFunctionCodeToRequest(Function function, Listing listing, DecompInterface decomp, JsonObject code_c) {
        AddressSetView addrSet = function.getBody();
        InstructionIterator codeUnits = listing.getInstructions(addrSet, true);

        JsonArray functionCode = new JsonArray();
        for (CodeUnit codeUnit : codeUnits) {
            JsonArray line = new JsonArray();
            line.add(codeUnit.getAddress().toString());
            line.add(codeUnit.toString());
            functionCode.add(line);
        }


        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        DecompileResults decompRes = decomp.decompileFunction(function, 0, monitor);
        code_c.addProperty(function.getName(), decompRes.getDecompiledFunction().getC());
//        return decompRes.getDecompiledFunction().getC();
    }


    protected void processAnalysisResponse(Program program, String responseJson, List<String> functionsNames) {
        try {

            ConsoleService consoleService = tool.getService(ConsoleService.class);
            if (responseJson.contains("No vulnerabilities detected")) {
                JOptionPane.showMessageDialog(null, "No vulnerabilities detected", "Analysis Result", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            JsonObject jsonObject = JsonParser.parseString(responseJson).getAsJsonObject();
            consoleService.addMessage("JSON response", jsonObject.toString() + "\n");
            JsonArray jsonArray = jsonObject.getAsJsonArray("comment");
//            consoleService.addMessage("jsonArray", jsonArray.toString());

            int maxLineLength = 55;
            int transaction = program.startTransaction("setComments");
            AddressFactory addressFactory = program.getAddressFactory();

            String line = "";
            String cwe = "";
            String comment = "";
            Color color = Color.MAGENTA;

            String full_comment = "";

            List<String> recap = new ArrayList<>();

            ArrayList<ArrayList<Address>> addressFinal = new ArrayList<>();


            for (JsonElement jsonElement : jsonArray) {
//                processComment(jsonElement, program, addressFactory, maxLineLength);

                JsonArray innerArray = jsonElement.getAsJsonArray();
                line = innerArray.get(0).getAsString();
                cwe = innerArray.get(1).getAsString();
                comment = innerArray.get(2).getAsString();
                color = parseColor(innerArray.get(3).getAsString());

                full_comment = cwe + " - " + comment;
                recap.add(full_comment);

                full_comment = cwe + " - " + comment + " - " + line;
                consoleService.addMessage("", full_comment);

                try {
                    for (String functionName : functionsNames) {
                        addressFinal.add(highlightAndCommentListingFromDecompiledString(functionName, line, full_comment, color));
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(null, "An error occurred: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }

            program.endTransaction(transaction, true);
            analyseDialog(recap, addressFinal);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void analyseDialog(List<String> recap, ArrayList<ArrayList<Address>> addressFinal) {
        // create a dialog Box
        JFrame frame = new JFrame("Analysis Result");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(500, 500);

        // create a list model
        DefaultListModel<String> listModel = new DefaultListModel<>();

        // add elements to the list model
        for (int i = 0; i < recap.size(); i++) {
            listModel.addElement(recap.get(i));
            // listModel.addElement(addressFinal.get(i).toString()); // Commented this line
        }

        // create a list
        JList<String> list = new JList<>(listModel);
        list.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        list.setLayoutOrientation(JList.VERTICAL);
        list.setVisibleRowCount(-1);

        // set the cell renderer to center the list items
        DefaultListCellRenderer renderer = (DefaultListCellRenderer) list.getCellRenderer();
        renderer.setHorizontalAlignment(SwingConstants.CENTER);

        // create a scroll pane and add the list to it
        JScrollPane scrollPane = new JScrollPane(list);

        // add a mouse listener to the list
        list.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent evt) {
                JList list = (JList) evt.getSource();
                if (evt.getClickCount() == 2) { // Double-click detected
                    int index = list.locationToIndex(evt.getPoint());
                    // navigate to the address when an item is double clicked
//                if (index % 2 == 0) { // if it's a recap item
                    ArrayList<Address> addresses = addressFinal.get(index);
                    if (!addresses.isEmpty()) {
                        GoToService goToService = tool.getService(GoToService.class);
                        if (goToService != null) {
                            goToService.goTo(addresses.get(0));
                        }
//                    }
                    }
                }
            }
        });

        // add the scroll pane to the frame
        frame.getContentPane().add(scrollPane, BorderLayout.CENTER);

        // make the frame visible
        frame.setVisible(true);
    }



    private Color parseColor(String colorStr) {
        return switch (colorStr.toLowerCase()) {
            case "yellow", "low" -> Color.YELLOW;
            case "red", "high" -> Color.RED;
            case "orange", "medium" -> Color.ORANGE;
            default -> Color.lightGray;
        };
    }



    protected void setMultilineComment(CodeUnit codeUnit, String comment, int maxLineLength) {
        StringBuilder formattedComment = new StringBuilder();
        String[] words = comment.split(" ");
        StringBuilder line = new StringBuilder();

        for (String word : words) {
            if (line.length() + word.length() > maxLineLength) {
                formattedComment.append(line).append("\n");
                line = new StringBuilder();
            }
            line.append(word).append(" ");
        }

        if (!line.isEmpty()) {
            formattedComment.append(line);
        }

        codeUnit.setComment(CodeUnit.PLATE_COMMENT, formattedComment.toString());
    }

    public ArrayList<Address> highlightAndCommentListingFromDecompiledString(String _functionName, String _line, String _comment, Color _color) {
        if (_functionName == null || _functionName.isEmpty()) {
            throw new IllegalArgumentException("Function name cannot be null or empty");
        }
        if (_line == null || _line.isEmpty()) {
            throw new IllegalArgumentException("Line cannot be null or empty");
        }
        if (_comment == null) {
            throw new IllegalArgumentException("Comment cannot be null");
        }
        if (_color == null) {
            throw new IllegalArgumentException("Color cannot be null");
        }

        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("Function name", _functionName + "\n");
        try {
            if (program == null) {
                throw new Exception("No current program");
            }

            Function function = getFunctionByName(_functionName);
            if (function == null) {
                throw new Exception("No function found");
            }
//            consoleService.addMessage("Function found ", function.getName() + "\n");


            ClangTokenGroup tokenGroup = getDecompiledTokens(function);
            if (tokenGroup == null) {
                throw new Exception("No token group found");
            }
//            consoleService.addMessage("Token group found ", tokenGroup + "\n");


            String[] lines = _line.split(";");
            ArrayList<Address> addressFinal = new ArrayList<>();

            for (String line : lines) {
                ArrayList<Address> address = getDecompiledAddressFromLine(tokenGroup, line, 0);
                if (address == null) {
                    throw new Exception("No address found");
                }

                setColorOnMultipleAddresses(address, _color);
                // remove duplicate adresse in array
                Set<Address> set = new LinkedHashSet<>(address);
                address.clear();
                address.addAll(set);
                addressFinal.addAll(address);
                consoleService.addMessage("Address found ", address + "\n");
                Listing listing = program.getListing();
                if (listing == null) {
                    throw new Exception("No listing found");
                }
                setMultilineComment(listing.getCodeUnitAt(address.get(0)), _comment, 55);
            }
//            listing.setComment(address.get(0), CodeUnit.PLATE_COMMENT, _comment);
            return addressFinal;

        } catch (Exception e) {
            consoleService.addErrorMessage("Error", e.getMessage());
        }
        return null;
    }

    private Function getFunctionByName(String _functionName) {
        if (program == null) {
            Msg.error(this, "No current program");
            return null;
        }
        FunctionIterator functionIterator = program.getListing().getFunctions(true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (function.getName().equals(_functionName)) {
                return function;
            }
        }
        return null;
    }

    private ClangTokenGroup getDecompiledTokens(Function _function) {
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(program);
        DecompileResults decompResults = decompInterface.decompileFunction(_function, 60, null);
        if (decompResults != null) {
            return decompResults.getCCodeMarkup();
        }
        return null;
    }


    private ArrayList<Address> getDecompiledAddressFromLine(ClangNode _node, String _line, int _index) {
        if (_node == null || _line == null || _line.isEmpty()) {
            throw new IllegalArgumentException("Node and line cannot be null or empty");
        }
        if (!_node.toString().contains(_line))
            return null;

//        ConsoleService consoleService = tool.getService(ConsoleService.class);

        int numChildren = _node.numChildren();
//        consoleService.addMessage("", "numChildren: " + numChildren + "\n");

        for (int i = 0; i < numChildren; i++) {
            ClangNode child = _node.Child(i);
//            consoleService.addMessage("",_node.toString() + "\n");

//            consoleService.addMessage("", "\t".repeat(_index) + child + "\n");
            if (!child.toString().contains(_line)) {
                continue;
            }
//            consoleService.addMessage("", "Found: ");
//            consoleService.addMessage("", "\t".repeat(_index) + child + "\n");
            ArrayList<Address> address = getDecompiledAddressFromLine(child, _line, _index + 1);
            if (address == null) {
                continue;
            }
            return address;

        }
        String tmp = "";
        ArrayList<Address> ret = new ArrayList<>();
        for (int i = 0; i < numChildren; i++) {
            ClangNode child = _node.Child(i);
            if (child.toString().isEmpty() || child.toString().equals(" ")) {
                continue;
            }
            if (_line.contains(child.toString())) {
                tmp = tmp.concat(child.toString());
                Address childMinAddress = child.getMinAddress();
                Address childMaxAddress = child.getMaxAddress();
                if (childMinAddress != null && childMaxAddress != null) {
                    ret.add(childMinAddress);
                    ret.add(childMaxAddress);
                }
                if (tmp.equals(_line)) {
                    break;
                }
            }
        }
        if (!tmp.isEmpty()) {
            return ret;
        }

        return null;
    }

    public void setColorOnMultipleAddresses(ArrayList<Address> _addresses, Color _color) {
        if (_addresses == null) {
            throw new IllegalArgumentException("Addresses cannot be null");
        }
        if (_color == null) {
            throw new IllegalArgumentException("Color cannot be null");
        }

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");

        for (int i = 0; i < _addresses.size(); i += 2) {
            Address start = _addresses.get(i);
            Address end = _addresses.get(i + 1);
            service.setBackgroundColor(start, end, _color);
        }


        program.endTransaction(TransactionID, true);
    }


}