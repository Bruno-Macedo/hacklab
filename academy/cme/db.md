#  "SELECT name FROM master.dbo.sysdatabases"

 "SELECT * from [DB].[dbo].tbl_users"

  master
tempdb
model
msdb
interns

## master
"SELECT * from [master].[dbo].spt_fallback_db" -- X
"SELECT * from [master].[dbo].spt_fallback_dev" -- X
"SELECT * from [master].[dbo].spt_fallback_usg" -- X
"SELECT * from [master].[dbo].spt_values" -- X
"SELECT * from [master].[dbo].spt_monitor" -- X
"SELECT * from [master].[dbo].spt_fallback_db"
spt_fallback_db
spt_fallback_dev
spt_fallback_usg
spt_values
spt_monitor


## tempdb

## msdb
-  "SELECT table_name from msdb.INFORMATION_SCHEMA.TABLES"
syspolicy_policy_category_subscriptions -- X
syspolicy_system_health_state -- X
syspolicy_policy_execution_history -- X
syspolicy_policy_execution_history_details -- X
syspolicy_configuration -- X
syspolicy_conditions -- X
syspolicy_policy_categories -- X
sysdac_instances -- X
syspolicy_object_sets -- X
dm_hadr_automatic_seeding_history -- X
syspolicy_policies -- X
backupmediaset -- X
backupmediafamily -- X
??? backupset 
backupfile -- X
syspolicy_target_sets -- X
restorehistory -- X
restorefile -- X
syspolicy_target_set_levels -- X
syspolicy_target_set_levels -- X
logmarkhistory -- X
suspect_pages
