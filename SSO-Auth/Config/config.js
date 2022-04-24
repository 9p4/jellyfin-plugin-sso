const ssoConfigurationPage = {
    pluginUniqueId: '505ce9d1-d916-42fa-86ca-673ef241d7df',
    loadConfiguration: (page) => {
        ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then((config) => {

            ssoConfigurationPage.populateProviders(page, config.OidConfigs);


        });
    },
    populateProviders: (page, providers) => {

        // Clear providers in case there are out of date ones
        page.querySelector("#selectProvider").querySelectorAll("option").forEach(option => {
            option.remove();
        });

        // Add providers as options for the selector

        Object.keys(providers).forEach(
            ( provider_name ) => {
                var choice = new Option(
                    provider_name,
                    provider_name
                    );
                    
                    page.querySelector("#selectProvider").appendChild(choice);
            });
    },
    listArgumentsByType : (page) => {
        const json_fields = ["EnabledFolders", "FolderRoleMapping", "Roles", "AdminRoles"];

        const text_fields = [...page.querySelectorAll("input[type='text']")].map( e => e.id).filter( id => ! json_fields.includes(id));

        const check_fields = [...page.querySelectorAll("input[type='checkbox']")].map( e => e.id);

        const output = { json_fields, text_fields, check_fields};

        return output;

    }, 
    loadProvider : (page, provider_name) => {

        ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => { 
            var provider = config.OidConfigs[provider_name] || {};

            const form_elements = ssoConfigurationPage.listArgumentsByType(page);

            page.querySelector("#OidProviderName").value = provider_name;
    
    
            form_elements.text_fields.forEach(( id ) => {
                if (provider[id]) page.querySelector("#"+id).value = provider[id];
            });
    
            form_elements.json_fields.forEach( (id ) => {
                if (provider[id]) page.querySelector("#"+id).value = JSON.stringify(provider[id]);
            });
    
            form_elements.check_fields.forEach( ( id ) => {
                if (provider[id]) page.querySelector("#"+id).checked = provider[id];
            });

        });

    },
    deleteProvider : (page, provider_name) => {
        return new Promise( (resolve ) => {
            ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => {
                if (!config.OidConfigs.hasOwnProperty(provider_name)) {
                    resolve();
                    return;
                }
                
                delete config.OidConfigs[provider_name];
                ApiClient.updatePluginConfiguration(ssoConfigurationPage.pluginUniqueId, config).then(function (result) {
                    Dashboard.processPluginConfigurationUpdateResult(result);
                    ssoConfigurationPage.loadConfiguration(page);

                    Dashboard.alert('Provider removed');

                    resolve();
                });
                
            });
        });

    },
    saveProvider : (page, provider_name) => {
        return new Promise( (resolve ) => {
            const form_elements = ssoConfigurationPage.listArgumentsByType(page);

            ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => {
                var current_config = {};
                if (config.OidConfigs.hasOwnProperty(provider_name)) {
                    current_config = config.OidConfigs[provider_name];
                }

                form_elements.text_fields.forEach(( id ) => {
                    const value = page.querySelector("#"+id).value;
                    if (value) current_config[id] = page.querySelector("#"+id).value;
                });

                form_elements.json_fields.forEach( (id ) => {
                    const value = page.querySelector("#"+id).value;
                    if (value) current_config[id] = JSON.parse(value);
                });

                form_elements.check_fields.forEach( ( id ) => {
                    current_config[id] = page.querySelector("#"+id).checked;
                });

                config.OidConfigs[provider_name] = current_config;

                ApiClient.updatePluginConfiguration(ssoConfigurationPage.pluginUniqueId, config).then(function (result) {
                    Dashboard.processPluginConfigurationUpdateResult(result);
                    ssoConfigurationPage.loadConfiguration(page);
                    ssoConfigurationPage.loadProvider(page, provider_name);


                    page.querySelector("#selectProvider").value = provider_name;
                    Dashboard.alert('Settings saved.');
                    resolve();

    
            });
    
    

        });
    });
 
    },

};

export default function (view) {
    ssoConfigurationPage.loadConfiguration(view);

    ssoConfigurationPage.listArgumentsByType(view);

    view.querySelector("#SaveProvider")
        .addEventListener("click", e => {

            const target_provider = view.querySelector("#OidProviderName").value;

            ssoConfigurationPage.saveProvider(view, target_provider);

            e.preventDefault();
            return false;

        });

    view.querySelector("#LoadProvider")
        .addEventListener("click", e => {

            const target_provider = view.querySelector("#selectProvider").value;

            ssoConfigurationPage.loadProvider(view, target_provider);

            e.preventDefault();
            return false;

        });

    view.querySelector("#DeleteProvider")
        .addEventListener("click", e => {

            const target_provider = view.querySelector("#selectProvider").value;

            ssoConfigurationPage.deleteProvider(view, target_provider);

            e.preventDefault();
            return false;

        });

        


    
};



