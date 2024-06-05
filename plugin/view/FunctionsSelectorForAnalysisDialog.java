package raverside.view;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class FunctionsSelectorForAnalysisDialog extends JDialog {
    private final List<String> functionsNames;
    private final List<JCheckBox> checkBoxes;
    private boolean confirmed = false;

    public FunctionsSelectorForAnalysisDialog(Frame owner, List<String> functions) {
        super(owner, "Functions to Analyse", true);
        this.functionsNames = functions;
        this.checkBoxes = new ArrayList<>();
        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        JPanel renamePanel = createRenamePanel();
        JScrollPane scrollPane = new JScrollPane(renamePanel);
        JPanel buttonPanel = createButtonPanel();

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setSize(400, 300);
        setLocationRelativeTo(getOwner());
    }

    private JPanel createRenamePanel() {
        JPanel renamePanel = new JPanel();
        renamePanel.setLayout(new BoxLayout(renamePanel, BoxLayout.Y_AXIS));

        for (String item : functionsNames) {
            JPanel itemPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JCheckBox checkBox = new JCheckBox(item);
            checkBoxes.add(checkBox);
            itemPanel.add(checkBox);
            renamePanel.add(itemPanel);
        }

        return renamePanel;
    }

    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel();
        JButton confirmButton = new JButton("Confirm");
        JButton cancelButton = new JButton("Cancel");

        confirmButton.addActionListener(e -> {
            confirmed = true;
            setVisible(false);
        });

        cancelButton.addActionListener(e -> setVisible(false));

        buttonPanel.add(confirmButton);
        buttonPanel.add(cancelButton);

        return buttonPanel;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public List<String> getSelectedItems() {
        List<String> selectedItems = new ArrayList<>();
        for (int i = 0; i < checkBoxes.size(); i++) {
            if (checkBoxes.get(i).isSelected()) {
                selectedItems.add(functionsNames.get(i));
            }
        }
        return selectedItems;
    }
}
