CREATE DATABASE auth;
USE auth;

DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id int(10) unsigned NOT NULL AUTO_INCREMENT,
  created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  email varchar(255) NOT NULL,
  password varchar(255) NOT NULL,
  name varchar(255) DEFAULT NULL,
  secret_key varchar(255) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY unique_email (email)
) ENGINE = InnoDB AUTO_INCREMENT = 6 DEFAULT CHARSET = latin1