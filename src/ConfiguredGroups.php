<?php

namespace Fromholdio\ConfiguredGroups;

use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;

class ConfiguredGroups extends DataExtension
{
    private static $configured_groups;

    public function requireDefaultRecords()
    {
        $config = $this->getOwner()->config()->get('configured_groups');
        if (!empty($config) && is_array($config))
        {
            foreach ($config as $code => $data) {
                $this->getOwner()->createConfiguredGroup($code, $data);
            }

            if (!isset($data['content-authors']))
            {
                $defaultGroup = Group::get()->find('Code', 'content-authors');
                if ($defaultGroup && $defaultGroup->exists()) {
                    $defaultGroup->delete();
                }
            }

            if (!isset($data['administrators']))
            {
                $configuredAdminCodes = $this->getOwner()->getAllConfiguredGroupAdminCodes();
                $adminGroups = Permission::get_groups_by_permission('ADMIN')->exclude('Code', 'administrators');
                if (!empty($configuredAdminCodes) && $adminGroups->count() > 0)
                {
                    $defaultAdminGroup = Group::get()->find('Code', 'administrators');
                    if ($defaultAdminGroup && $defaultAdminGroup->exists()) {
                        $defaultAdminGroup->delete();
                    }
                }
            }
        }
    }

    public function getAllConfiguredGroupAdminCodes(): array
    {
        $codes = [];
        $config = $this->getOwner()->config()->get('configured_groups');
        if (!empty($config) && is_array($config))
        {
            foreach ($config as $code => $data)
            {
                $groupAdminCodes = $this->getOwner()->getConfiguredGroupAdminCodes($code, $data, true);
                if (!empty($groupAdminCodes)) {
                    $codes += $groupAdminCodes;
                }
            }
        }
        return $codes;
    }

    public function getConfiguredGroupAdminCodes(string $code, array $data, bool $checkChildren = false): array
    {
        $codes = [];
        if ($this->getOwner()->isConfiguredGroupAdmin($data)) {
            $codes[] = $code;
        }

        $children = $data['children'] ?? null;
        if (!empty($children) && is_array($children)) {
            foreach ($children as $childCode => $childData) {
                $childAdminCodes = $this->getOwner()->getConfiguredGroupAdminCodes($childCode, $childData, $checkChildren);
                if (!empty($childAdminCodes)) {
                    $codes += $childAdminCodes;
                }
            }
        }
        return $codes;
    }

    public function isConfiguredGroupAdmin(array $data, bool $checkChildren = false): bool
    {
        $isAdmin = false;

        $permissions = $data['permissions'] ?? null;
        if (!empty($permissions) && is_array($permissions)) {
            $isAdmin = in_array('ADMIN', $permissions);
        }

        if (!$isAdmin && $checkChildren)
        {
            $children = $data['children'] ?? null;
            if (!empty($children) && is_array($children)) {
                foreach ($children as $childData) {
                    $isAdmin = $this->getOwner()->isConfiguredGroupAdmin($childData, $checkChildren);
                    if ($isAdmin) break;
                }
            }
        }

        return $isAdmin;
    }

    public function createConfiguredGroup(string $code, array $data, int $parentGroupID = 0): void
    {
        $title = $data['title'] ?? $code;
        $sort = $data['sort'] ?? null;
        $permissions = $data['permissions'] ?? null;
        $children = $data['children'] ?? null;

        $group = Group::get()->find('Code', $code);
        if (!$group || !$group->exists())
        {
            $group = Group::create();
            $group->Code = $code;
        }

        $group->Title = $title;
        $group->Sort = $sort;
        $group->ParentID = $parentGroupID;
        $group->write();

        if (!empty($permissions) && is_array($permissions)) {
            foreach ($permissions as $permission) {
                Permission::grant($group->ID, $permission);
            }
        }

        if (!empty($children) && is_array($children))
        {
            $groupID = (int) $group->ID;
            foreach ($children as $childCode => $childData) {
                $this->getOwner()->createConfiguredGroup($childCode, $childData, $groupID);
            }
        }
    }
}
