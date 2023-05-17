<?php

namespace Fromholdio\ConfiguredGroups;

use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\ORM\ArrayList;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;

class ConfiguredGroups extends DataExtension
{
    private static $configured_groups;

    private static $is_configured_permissions_only = false;
    private static $is_configured_root_groups_only = false;


    public function requireDefaultRecords()
    {
        $config = $this->getOwner()->getConfiguredGroupsConfig();
        if (empty($config)) return;
        $this->doConfigureGroups($config);
    }


    public function doConfigureGroups(array $config): void
    {
        if (empty($config)) return;

        foreach ($config as $code => $data) {
            $this->getOwner()->doConfigureGroup($code, $data);
        }

        // Delete not-configured root-level groups if only configured groups allowed
        if ($this->getOwner()->isConfiguredRootGroupsOnly())
        {
            $rootGroups = Group::get()
                ->filter('ParentID', 0)
                ->exclude('Code', 'administrators');
            foreach ($rootGroups as $rootGroup) {
                if (!$rootGroup->isConfiguredGroup()) {
                    $rootGroup->delete();
                }
            }
        }

        // Delete default administrators group,
        // if other group has been configured with ADMIN permission
        if (!$this->getOwner()->isConfiguredGroup('administrators'))
        {
            $configuredAdminCodes = $this->getOwner()->getAllConfiguredAdminGroupCodes();
            $adminGroups = Permission::get_groups_by_permission('ADMIN')->exclude('Code', 'administrators');
            if (!empty($configuredAdminCodes) && $adminGroups->count() > 0)
            {
                $defaultAdminGroup = Group::get()->find('Code', 'administrators');
                if ($defaultAdminGroup?->exists()) {
                    $defaultAdminGroup->delete();
                }
            }
        }
    }

    public function doConfigureGroup(string $code, array $config, int $parentGroupID = 0): void
    {
        $title = $config['title'] ?? $code;
        $description = $config['description'] ?? null;
        $sort = $config['sort'] ?? null;
        $permissions = $config['permissions'] ?? null;
        $children = $config['children'] ?? null;
        $isConfigChildrenOnly = $config['is_configured_children_only'] ?? false;

        $group = Group::get()->find('Code', $code);
        if (!$group || !$group->exists())
        {
            $group = Group::create();
            $group->setField('Code', $code);
        }

        $group->setField('Title', $title);
        $group->setField('Description', $description);
        $group->setField('Sort', $sort);
        $group->setField('ParentID', $parentGroupID);
        $group->write();
        $groupID = (int) $group->getField('ID');

        if (!empty($permissions) && is_array($permissions))
        {
            if ($this->getOwner()->isConfiguredPermissionsOnly())
            {
                $unconfigPermissions = Permission::get()
                    ->filter('GroupID', $groupID)
                    ->exclude('Code', array_values($permissions));
                foreach ($unconfigPermissions as $unconfigPermission) {
                    $unconfigPermission->delete();
                }
            }
            foreach ($permissions as $permission)
            {
                $existingPermission = Permission::get()->filter([
                    'GroupID' => $groupID,
                    'Code' => $permission
                ])->first();
                if (!$existingPermission?->exists()) {
                    Permission::grant($groupID, $permission);
                }
            }
        }

        if (!empty($children) && is_array($children))
        {
            foreach ($children as $childCode => $childData) {
                $this->getOwner()->doConfigureGroup($childCode, $childData, $groupID);
            }
            if ($isConfigChildrenOnly) {
                $childGroups = Group::get()->filter('ParentID', $groupID);
                foreach ($childGroups as $childGroup) {
                    if (!$childGroup->isConfiguredGroup()) {
                        $childGroup->delete();
                    }
                }
            }
        }
    }


    public function getConfiguredGroupsConfig(): array
    {
        $config = $this->getOwner()->config()->get('configured_groups');
        $this->getOwner()->invokeWithExtensions('updateConfiguredGroupsConfig', $config);
        return empty($config) || !is_array($config) ? [] : $config;
    }

    public function getConfiguredGroupConfig(string $code): ?array
    {
        $config = $this->getOwner()->getAllConfiguredGroupsConfig();
        if (empty($config)) return null;
        $codeConfig = $config[$code] ?? null;
        return is_array($codeConfig) ? $codeConfig : null;
    }

    public function getConfiguredGroupConfigValue(string $key, ?string $code = null): array|string|bool|null
    {
        if (empty($code)) {
            $code = $this->getOwner()->getField('Code');
        }
        if (empty($code)) {
            return null;
        }
        $config = $this->getOwner()->getConfiguredGroupConfig($code);
        return $config[$key] ?? null;
    }


    public function getAllConfiguredGroupsConfig(?array $config = null): array
    {
        $allConfig = [];
        if (is_null($config)) {
            $config = $this->getOwner()->getConfiguredGroupsConfig();
            if (empty($config)) return $allConfig;
        }
        foreach ($config as $key => $data)
        {
            $allConfig[$key] = $data;
            $childrenConfig = $data['children'] ?? null;
            if (!empty($childrenConfig)) {
                $allChildrenConfig = $this->getOwner()->getAllConfiguredGroupsConfig($childrenConfig);
                if (!empty($allChildrenConfig)) {
                    $allConfig = [...$allConfig, ...$allChildrenConfig];
                }
            }
        }
        return $allConfig;
    }

    public function getAllConfiguredGroupCodes(): array
    {
        $config = $this->getOwner()->getAllConfiguredGroupsConfig();
        return empty($config) ? [] : array_keys($config);
    }

    public function getAllConfiguredAdminGroupCodes(): array
    {
        $adminCodes = [];
        $config = $this->getOwner()->getAllConfiguredGroupCodes();
        foreach ($config as $code) {
            if ($this->getOwner()->isConfiguredAdminGroup('ADMIN', $code)) {
                $adminCodes[] = $code;
            }
        }
        return $adminCodes;
    }

    /**
     * Return codes of configured groups that allow configured & non-configured (added new by cms user) groups as children.
     * @return array
     */
    public function getAllConfiguredGroupCodesAllowNewChildren(): array
    {
        $codes = [];
        $allCodes = $this->getOwner()->getAllConfiguredGroupCodes();
        foreach ($allCodes as $code) {
            if (!$this->getOwner()->isConfiguredChildGroupsOnly($code)) {
                $codes[] = $code;
            }
        }
        return $codes;
    }

    /**
     * Return codes of configured groups that allow only configured groups as children.
     * @return array
     */
    public function getAllConfiguredGroupCodesDisallowNewChildren(): array
    {
        $codes = [];
        $allCodes = $this->getOwner()->getAllConfiguredGroupCodes();
        foreach ($allCodes as $code) {
            if ($this->getOwner()->isConfiguredChildGroupsOnly($code)) {
                $codes[] = $code;
            }
        }
        return $codes;
    }


    public function isConfiguredGroupsOnly(): bool
    {
        return $this->getOwner()->isConfiguredRootGroupsOnly()
            && empty($this->getOwner()->getAllConfiguredGroupCodesAllowNewChildren());
    }

    public function isConfiguredRootGroupsOnly(): bool
    {
        return (bool) $this->getOwner()->config()->get('is_configured_root_groups_only');
    }

    public function isConfiguredPermissionsOnly(): bool
    {
        return (bool) $this->getOwner()->config()->get('is_configured_permissions_only');
    }


    public function isConfiguredGroup(?string $code = null): bool
    {
        if (empty($code)) {
            $code = $this->getOwner()->getField('Code');
        }
        if (empty($code)) {
            return false;
        }
        $config = $this->getOwner()->getConfiguredGroupConfig($code);
        return !empty($config);
    }

    public function isConfiguredAdminGroup(?string $code = null): bool
    {
        return $this->getOwner()->isConfiguredGroupPermitted('ADMIN', $code);
    }

    public function isConfiguredGroupPermitted(string $permissionCode, ?string $code = null): bool
    {
        if (empty($code)) {
            $code = $this->getOwner()->getField('Code');
        }
        if (!$this->getOwner()->isConfiguredGroup($code)) {
            return false;
        }
        $permissions = $this->getOwner()->getConfiguredGroupConfigValue('permissions', $code);
        if (!is_array($permissions)) {
            return false;
        }
        return in_array($permissionCode, $permissions);
    }

    public function isConfiguredChildGroupsOnly(?string $code = null): bool
    {
        if (empty($code)) {
            $code = $this->getOwner()->getField('Code');
        }
        if (!$this->getOwner()->isConfiguredGroup($code)) {
            return false;
        }
        return (bool) $this->getOwner()->getConfiguredGroupConfigValue('is_configured_children_only', $code);
    }


    public function validate(ValidationResult $validationResult): void
    {
        if (!$this->getOwner()->isConfiguredGroup())
        {
            if ($this->getOwner()->isConfiguredGroupsOnly()) {
                $validationResult->addError('Groups must be managed via configuration only.');
            }
            else {
                $parent = $this->getOwner()->Parent();
                if ($parent?->exists()) {
                    if ($parent->isConfiguredChildGroupsOnly()) {
                        $validationResult->addError('You must select a valid parent group.');
                    }
                }
                elseif ($this->getOwner()->isConfiguredRootGroupsOnly()) {
                    $validationResult->addError('You must select a valid parent group.');
                }
            }
        }
    }


    public function getConfiguredDecodedBreadcrumbs(): ArrayList
    {
        $list = ArrayList::create();
        if (!$this->getOwner()->isConfiguredGroupsOnly())
        {
            $groups = Group::get()->exclude('ID', $this->getOwner()->getField('ID'));
            $disallowNewChildCodes = $this->getOwner()->getAllConfiguredGroupCodesDisallowNewChildren();
            if (!empty($disallowNewChildCodes)) {
                $groups = $groups->exclude('Code', $disallowNewChildCodes);
            }
            $member = Security::getCurrentUser();
            foreach ($groups as $group) {
                if ($group->canView($member)) {
                    $list->push([
                        'ID' => $group->getField('ID'),
                        'Title' => $group->getBreadcrumbs(' » ')
                    ]);
                }
            }
        }
        return $list;
    }

    public function updateCMSFields(FieldList $fields): void
    {
        if ($this->getOwner()->isConfiguredGroup()) {
            $fields->dataFieldByName('Title')->setReadonly(true);
            if (empty($this->getOwner()->getField('Description'))) {
                $fields->removeByName('Description');
            }
            else {
                $fields->dataFieldByName('Description')?->setReadonly(true);
            }
            if ($this->getOwner()->Parent()?->exists()) {
                $parentIDField = ReadonlyField::create(
                    'ParentBreadcrumbs',
                    $this->getOwner()->fieldLabel('Parent'),
                    $this->getOwner()->Parent()->getBreadcrumbs(' » ')
                );
                $fields->replaceField('ParentID', $parentIDField);
            }
            else {
                $fields->removeByName('ParentID');
            }
            if ($this->getOwner()->isConfiguredPermissionsOnly()) {
                $fields->dataFieldByName('Permissions')?->setReadonly(true);
            }
            return;
        }

        /** @var DropdownField $parentIDField */
        $parentIDField = $fields->dataFieldByName('ParentID');
        if (!$parentIDField) return;

        $configuredParentsList = $this->getConfiguredDecodedBreadcrumbs();
        if ($configuredParentsList->count() > 0) {
            $parentIDField->setSource($configuredParentsList);
            if ($this->getOwner()->isConfiguredRootGroupsOnly()) {
                $parentIDField->setHasEmptyDefault(false);
            }
        }
        else {
            $fields->removeByName('ParentID');
        }
    }


    public function canCreate($member): bool
    {
        if ($this->getOwner()->isConfiguredGroupsOnly()) {
            return false;
        }
        return Permission::checkMember($member, 'CMS_ACCESS_SecurityAdmin');
    }

    public function canView($member): ?bool
    {
        if ($this->getOwner()->isConfiguredGroup()) {
            $isHidden = (bool) $this->getOwner()->getConfiguredGroupConfigValue('is_hidden');
            if ($isHidden) {
                $canView = false;
                if ($member?->exists()) {
                    $canView = $member->inGroup($this->getOwner(), true);
                }
                return $canView;
            }
        }
        return null;
    }

    public function canDelete($member): ?bool
    {
        if ($this->getOwner()->isConfiguredGroup()) {
            return false;
        }
        return null;
    }
}
