create table tokens(
    loginname varchar(64) not null,
    password varchar(64) not null,
    oauth_token varchar(64) not null, 
    oauth_secret varchar(64) not null,
    addtime  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (loginname) ON CONFLICT REPLACE
);

create index tokens_namepass     on tokens ( loginname,password );
create index tokens_password     on tokens ( password  );
create index tokens_oauth_token  on tokens ( oauth_token  );
create index tokens_oauth_secret on tokens ( oauth_secret );
