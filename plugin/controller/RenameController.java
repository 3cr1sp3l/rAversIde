package raverside.controller;

import raverside.model.RenameItem;
import raverside.view.RenameDialog;

import java.awt.*;
import java.util.List;

public class RenameController {
    private final Frame owner;
    private final List<RenameItem> renameItems;

    public RenameController(Frame owner, List<RenameItem> renameItems) {
        this.owner = owner;
        this.renameItems = renameItems;
    }

    public List<RenameItem> showRenameDialog() {
        RenameDialog dialog = new RenameDialog(owner, renameItems);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
           return dialog.getSelectedItems();
        }
        return null;
    }
}
