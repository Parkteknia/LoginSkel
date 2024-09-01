SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

CREATE TABLE blocked_ips (
  id int(11) NOT NULL,
  ip_address varchar(45) NOT NULL,
  blocked_at timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE config (
  conf_key varchar(255) NOT NULL,
  conf_value text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE `filters` (
  `id` int(11) NOT NULL,
  `filter_file` varchar(255) NOT NULL,
  `filter_description` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE jwt_tokens (
  id int(11) NOT NULL,
  jti varchar(255) NOT NULL,
  user_id int(11) NOT NULL,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  revoked_at timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE login_attempts (
  id int(11) NOT NULL,
  ip varchar(45) NOT NULL,
  user_agent text NOT NULL,
  attempt_time timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE refresh_tokens (
  id int(11) NOT NULL,
  token varchar(64) NOT NULL,
  jti varchar(255) NOT NULL,
  user_id int(11) NOT NULL,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  expires_at timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  revoked tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE register_attempts (
  id int(11) NOT NULL,
  ip_address varchar(45) NOT NULL,
  user_agent text NOT NULL,
  attempt_username varchar(255) DEFAULT NULL,
  attempt_email varchar(255) DEFAULT NULL,
  attempted_at timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE roles (
  id int(11) NOT NULL,
  name varchar(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE tokens (
  id int(11) NOT NULL,
  user_id int(11) NOT NULL,
  token varchar(255) NOT NULL,
  generated_at timestamp NOT NULL DEFAULT current_timestamp(),
  validated_at timestamp NULL DEFAULT NULL,
  unvalidated_at timestamp NULL DEFAULT NULL,
  status enum('valid','unvalid') DEFAULT 'valid',
  token_type enum('account_validate','password_reset') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `role_id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `secret_key` varchar(32) DEFAULT NULL,
  `activation_code` char(6) DEFAULT NULL,
  `2fa_conf` tinyint(1) NOT NULL,
  `status` enum('active','inactive') DEFAULT 'inactive',
  `code_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE user_sessions (
  session_id varchar(255) NOT NULL,
  user_session_id varchar(255) NOT NULL,
  user_id int(11) NOT NULL,
  ip_address varchar(45) NOT NULL,
  user_agent text NOT NULL,
  status enum('active','inactive','failed') DEFAULT 'active',
  start_activity timestamp NOT NULL DEFAULT current_timestamp(),
  last_activity timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;


ALTER TABLE blocked_ips
  ADD PRIMARY KEY (id),
  ADD UNIQUE KEY ip_address (ip_address);

ALTER TABLE config
  ADD PRIMARY KEY (conf_key);

ALTER TABLE filters
  ADD PRIMARY KEY (id),
  ADD UNIQUE KEY filter_file (filter_file);

ALTER TABLE jwt_tokens
  ADD PRIMARY KEY (id),
  ADD UNIQUE KEY jti (jti),
  ADD KEY user_id (user_id);

ALTER TABLE login_attempts
  ADD PRIMARY KEY (id);

ALTER TABLE refresh_tokens
  ADD PRIMARY KEY (id),
  ADD UNIQUE KEY token (token),
  ADD KEY fk_refresh_tokens_user_id (user_id);

ALTER TABLE register_attempts
  ADD PRIMARY KEY (id);

ALTER TABLE roles
  ADD PRIMARY KEY (id),
  ADD UNIQUE KEY name (name);

ALTER TABLE tokens
  ADD PRIMARY KEY (id),
  ADD KEY fk_user_id (user_id) USING BTREE;

ALTER TABLE users
  ADD PRIMARY KEY (id),
  ADD UNIQUE KEY unique_username (username),
  ADD UNIQUE KEY unique_email (email),
  ADD KEY fk_role_id (role_id);

ALTER TABLE user_sessions
  ADD PRIMARY KEY (session_id),
  ADD UNIQUE KEY user_session_id (user_session_id),
  ADD KEY fk_user_sessions_user_id (user_id);


ALTER TABLE blocked_ips
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE jwt_tokens
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE login_attempts
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE refresh_tokens
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE register_attempts
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE roles
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE tokens
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE users
  MODIFY id int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE refresh_tokens
  ADD CONSTRAINT fk_refresh_tokens_user_id FOREIGN KEY (user_id) REFERENCES `users` (id);

ALTER TABLE tokens
  ADD CONSTRAINT fk_tokens_user_id FOREIGN KEY (user_id) REFERENCES `users` (id);

ALTER TABLE users
  ADD CONSTRAINT fk_role_id FOREIGN KEY (role_id) REFERENCES `roles` (id);

ALTER TABLE user_sessions
  ADD CONSTRAINT fk_user_sessions_user_id FOREIGN KEY (user_id) REFERENCES `users` (id);
COMMIT;

INSERT INTO `roles` (`id`, `name`) VALUES
(1, 'admin'),
(2, 'user');

INSERT INTO `filters` (`id`, `filter_file`, `filter_description`) VALUES
(1, '10-million-password-list-top-10000.txt', 'https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;


