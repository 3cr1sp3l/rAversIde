package raverside.controller;


import raverside.view.FunctionsSelectorForAnalysisDialog;

import java.awt.*;
import java.util.List;

public class FunctionsController {
    private final Frame owner;
    private final List<String> functionsNames;

    public FunctionsController(Frame owner, List<String> functionsNames) {
        this.owner = owner;
        this.functionsNames = functionsNames;
    }

    public List<String> showFunctionsSelectorDialog() {
        FunctionsSelectorForAnalysisDialog dialog = new FunctionsSelectorForAnalysisDialog(owner, functionsNames);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            return dialog.getSelectedItems();

        }
        return null;
    }
}
