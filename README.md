# ObjC-StackBlock

A script for IDA Pro 9.0 that renames `__NSConcreteStackBlock` based callback functions.

## What?

When you see a structure in pseudocode like this:

```c
v11.isa = _NSConcreteStackBlock;
v11.flags = -1040187392;
v11.reserved = 0;
v11.invoke = sub_1000444F4;
v11.descriptor = &stru_101248218;
v11.lvar1 = objc_retain(v13);
```

You can determine that the `.invoke` field of the stack block will most likely be used as a callback. For easier xref at-a-glance analysis this plugin will rename the invoke'd function to be of the format `calledFrom_{SRCFUNC}` where `SRCFUNC` is the function in which the stackblock is located.

> **Note**
> If a function already has a custom name assigned in the database, the script will not touch it.


## Contributing

Clone the repo and make a PR :3 