create table people (id serial primary key, name text not null);
create index people_name on people (name);
