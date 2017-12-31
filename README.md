# Phalcon-ACL

This ACL utilizes the MVC URI routing as addresses to program actions so that
permissions can be assigned to them.

Permissions are store in a table as unique module, controller and action combinations

```sql
CREATE TABLE permission (
    id SERIAL PRIMARY KEY,
    name character varying(42) NOT NULL,
    module character varying(42) NOT NULL,
    controller character varying(42) NOT NULL,
    action character varying(42) NOT NULL,
    description text
);
```

In your module attach an event listener to the dispatcher and pass the module name

```php
$eventManager = new \Phalcon\Events\Manager();
$eventManager->attach('dispatch', new \Acl('manager'));
```