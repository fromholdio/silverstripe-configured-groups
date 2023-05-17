# silverstripe-configured-groups

Silverstripe module that provides mechanism to configure security groups via yml config.

## Requirements

- 2.x branch currently supports both SilverStripe 4 & 5.

## Rationale

For many sites, the core security groups and their key permissions should not be changed by CMS users. 

It leaves open the possibility of users breaking permission configurations, deletion of groups that would have consequential impacts throughout the site, and so forth.

Having these managed via CMS also means that developers moving & deploying between environments must port group configurations manually.

Instead, this module provides yml config:

- Configuration of groups, and their assigned permissions, initialised on dev/build
- If no ADMIN group is configured, the default 'administrators' group will remain in place
- Can force only configured groups as root groups (ie. CMS user cannot add new top-level groups)
- On per configured group basis, dis/allow CMS users adding new sub-groups (by extension, allowing or preventing CMS users adding new groups at all)
- Can force only configured permissions per group (ie. any permissions set via CMS checkbox, that are not in yml config, are deleted on dev/build)
- For configured groups, title, description and parent cms fields are read-only
- Where a configured group's permissions are set to only a configured set, the permissions checkbox set is read-only
- A configured group can be marked as hidden, and will not be displayed to users who are not direct members of that group (used to obfuscate the administrators group when only utilised by developers, for instance)

## Installation

Install the module using composer:

```
composer require fromholdio/silverstripe-configured-groups dev-master
```

Then apply your own group configuration (see below) and run dev/build.

## Config examples

- Out of the box, no configuration is applied, only the extension itself. You need to compose your groups configuration per example below: 

```yml
SilverStripe\Security\Group:
  is_configured_root_groups_only: true      # only configured groups as top-level (cms users cannot add new with parentID 0)
  is_configured_permissions_only: true      # only configured permissions on this group (others deleted during dev/build)
  configured_groups:
    administrators:                         # configured group code
      title: Administrators
      sort: 0
      is_hidden: true                       # hides group from view of non-direct-members
      permissions:                          # array of permission codes
        - ADMIN
    managers:     
      title: Site managers
      description: 'Primary non-developer super-user account type'
      sort: 1
      is_configured_children_only: true     # only configured groups as sub-groups (cms users cannot add new groups with parent ID as this group's ID)
      permissions:
        - CMS_ACCESS_CMSMain
        - CMS_ACCESS_AssetAdmin
        - CMS_ACCESS_ReportAdmin
        - CMS_ACCESS_SecurityAdmin
        - SITETREE_REORGANISE
        - EDIT_SITECONFIG
    previewers:
      title: Previewers
      sort: 2
      children:
        previewer-special:
          title: 'Special previewers'
          sort: 0
          permissions:
            - CMS_ACCESS_CMSMain
            - VIEW_DRAFT_CONTENT
        previewer-okay:
          title: 'Just okay previewers'
          sort: 1
          permissions:
            - VIEW_DRAFT_CONTENT
```

## License

BSD 3-Clause License, see [License](LICENSE)
