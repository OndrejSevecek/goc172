SELECT sess.program_name, sess.client_interface_name, conn.client_net_address, conn.client_tcp_port, conn.encrypt_option, sess.login_name, conn.auth_scheme
FROM sys.dm_exec_connections AS conn 
JOIN sys.dm_exec_sessions AS sess
ON conn.session_id = sess.session_id
WHERE conn.net_transport <> 'Shared memory'