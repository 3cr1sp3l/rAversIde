package raverside.model;

import ghidra.program.model.listing.Function;

public class RenameItem {
    private final String oldName;
    private String newName;
    private final String itemType;
    private final Function function;

    public RenameItem(String oldName, String newName, String itemType, Function function) {
        this.oldName = oldName;
        this.newName = newName;
        this.itemType = itemType;
        this.function = function;
    }

    public String getOldName() {
        return oldName;
    }

    public String getNewName() {
        return newName;
    }

    public String getItemType() {
        return itemType;
    }

    public Function getFunction() {
        return function;
    }

    public void setNewName(String newName) {
        this.newName = newName;
    }

    @Override
    public String toString() {
        return "RenameItem{" +
                "oldName='" + oldName + '\'' +
                ", newName='" + newName + '\'' +
                ", itemType='" + itemType + '\'' +
                ", function=" + (function != null ? function.getName() : "null") +
                '}';
    }
}

