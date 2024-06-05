package raverside;


import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import raverside.controller.ApiManager;
import raverside.controller.MyProviderController;
import raverside.view.MyProviderPanel;
import resources.ResourceManager;


import javax.swing.*;

public class MyProvider extends ComponentProviderAdapter {
    private final MyProviderPanel panel;
    private final MyProviderController controller;
    private MyProviderPanel view;
    private final RaversidePlugin plugin;

    public MyProvider(PluginTool tool, String name, RaversidePlugin plugin) {
        super(tool, name, name);
        panel = plugin.getPanel();
        controller = plugin.getProviderControler();
        this.plugin = plugin;
        setTitle(name);
        addToTool();

    }

    public void createActions() {
        Icon refreshIcon = ResourceManager.loadImage("images/refresh.png");
//        DockingAction refreshAction = new DockingAction("Refresh", getName()) {
//            @Override
//            public void actionPerformed(ActionContext context) {
//                controller.refresh();
//            }
//        };
//        refreshAction.setToolBarData(new ToolBarData(refreshIcon, null));
//        refreshAction.setEnabled(true);
//        refreshAction.markHelpUnnecessary();
//        refreshAction.setMenuBarData(new MenuData(new String[]{"MyProvider", "Refresh"}));
//        dockingTool.addAction(refreshAction);


        DockingAction refreshAction = new DockingAction("Refresh", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.refresh();
            }
        };
        refreshAction.setToolBarData(new ToolBarData(refreshIcon, null));
        refreshAction.setEnabled(true);
        refreshAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this.plugin.getProvider(), refreshAction);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
