create table pets (id serial primary key, owner int references people (id), name text not null);
