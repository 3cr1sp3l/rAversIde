package raverside.view;


import raverside.model.RenameItem;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class RenameDialog extends JDialog {
    private final List<RenameItem> renameItems;
    private final List<JCheckBox> checkBoxes;
    private boolean confirmed = false;

    public RenameDialog(Frame owner, List<RenameItem> renameItems) {
        super(owner, "Rename Proposals", true);
        this.renameItems = renameItems;
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

        for (RenameItem item : renameItems) {
            JPanel itemPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

            JCheckBox checkBox = new JCheckBox(formatRenameText(item));
            checkBoxes.add(checkBox);
            itemPanel.add(checkBox);

            JButton editButton = new JButton("Edit");
            editButton.addActionListener(e -> {
                String newName = JOptionPane.showInputDialog(this,
                        "Enter new name for " + item.getOldName() + ":",
                        item.getNewName());
                if (newName != null && !newName.trim().isEmpty()) {
                    item.setNewName(newName.trim());
                    checkBox.setText(formatRenameText(item));
                }
            });
            itemPanel.add(editButton);

            renamePanel.add(itemPanel);
        }

        return renamePanel;
    }

    private String formatRenameText(RenameItem item) {
        return item.getOldName() + " -> " + item.getNewName();
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

    public List<RenameItem> getSelectedItems() {
        List<RenameItem> selectedItems = new ArrayList<>();
        for (int i = 0; i < checkBoxes.size(); i++) {
            if (checkBoxes.get(i).isSelected()) {
                selectedItems.add(renameItems.get(i));
            }
        }
        return selectedItems;
    }
}
