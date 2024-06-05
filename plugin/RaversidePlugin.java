/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package raverside;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import raverside.controller.ApiManager;
import raverside.controller.FeatureManager;
import raverside.controller.MyProviderController;
import raverside.utils.Constants;
import raverside.utils.Helper;
import raverside.view.MyProviderPanel;

import java.net.URISyntaxException;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
		status = PluginStatus.STABLE,
		packageName = ExamplesPluginPackage.NAME,
		category = PluginCategoryNames.EXAMPLES,
		shortDescription = "Reverse Engineering Assistant",
		description = "Raverside is a reverse engineering assistant that provides various features to help reverse engineers."
		)
//@formatter:on
public class RaversidePlugin extends ProgramPlugin {

    MyProvider provider;
    Program program;
    private ApiManager apiManager;
    private FeatureManager featureManager;
    private Helper helper;
    private MyProviderController controller;
    private final MyProviderPanel panel;



    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     * @throws URISyntaxException
     * @throws InterruptedException
     */
    public RaversidePlugin(PluginTool tool) throws URISyntaxException, InterruptedException {
        super(tool);
        this.panel = new MyProviderPanel();
        this.panel.apiTextField.setText(Constants.API_TMP_KEY);

        this.featureManager = new FeatureManager(this);
        this.helper = new Helper(this);
        this.apiManager = new ApiManager(this);
        this.controller = new MyProviderController(this);
        // TODO: Customize provider (or remove if a provider is not desired)
        String pluginName = getName();
        provider = new MyProvider(tool, pluginName, this);
        provider.createActions();

        // TODO: Customize help (or remove if help is not desired)
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));

    }


    @Override
    public void init() {
        super.init();
    }

    @Override
    protected void programActivated(Program p) {
        program = p;
        controller.setProgram(p);
        controller.refresh();
    }

    public MyProviderController getProviderControler() {
        return controller;
    }

    public ApiManager getApiManager() {
        return apiManager;
    }

    public FeatureManager getFeatureManager() {
        return featureManager;
    }

    public MyProviderPanel getPanel() {
        return panel;
    }

    public Helper getHelper() {
        return helper;
    }

    public MyProvider getProvider() {
        return provider;
    }
}