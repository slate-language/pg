create table toys (id serial primary key, pet int references pets (id), name text not null);
