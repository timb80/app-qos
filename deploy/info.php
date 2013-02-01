<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'qos';
$app['version'] = '1.4.1';
$app['release'] = '1';
$app['vendor'] = 'ClearFoundation';
$app['packager'] = 'ClearFoundation';
$app['license'] = 'GPLv3';
$app['license_core'] = 'LGPLv3';
$app['description'] = lang('qos_app_description');
$app['core_only'] = TRUE;

/////////////////////////////////////////////////////////////////////////////
// App name and categories
/////////////////////////////////////////////////////////////////////////////

$app['name'] = lang('qos_app_name');
$app['category'] = lang('base_category_network');
$app['subcategory'] = lang('base_subcategory_bandwidth_and_qos');
$app['menu_enabled'] = FALSE;

/////////////////////////////////////////////////////////////////////////////
// Packaging
/////////////////////////////////////////////////////////////////////////////

$app['requires'] = array(
    'app-network',
);

$app['core_requires'] = array(
    'app-network-core',
    'app-firewall-core >= 1:1.4.15',
    'mtr',
);

$app['core_directory_manifest'] = array(
    '/var/clearos/qos' => array(),
);

$app['core_file_manifest'] = array(
    'qos.conf' => array(
        'target' => '/etc/clearos/qos.conf',
        'mode' => '0644',
        'owner' => 'root',
        'group' => 'root',
        'config' => TRUE,
        'config_params' => 'noreplace',
    ),
);

$app['delete_dependency'] = array(
    'app-qos-core'
);