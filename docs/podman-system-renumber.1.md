% podman-system-renumber(1)

## NAME
podman\-system\-renumber - Renumber container locks

## SYNOPSIS
**podman system renumber**

## DESCRIPTION
**podman system renumber** renumbers locks used by containers and pods.

Each Podman container and pod is allocated a lock at creation time, up to a maximum number controlled by the **num_locks** parameter in **libpod.conf**.

When all available locks are exhausted, no further containers and pods can be created until some existing containers and pods are removed. This can be avoided by increasing the number of locks available via modifying **libpod.conf** and subsequently running **podman system renumber** to prepare the new locks (and reallocate lock numbers to fit the new struct).

**podman system renumber** must be called after any changes to **num_locks** - failure to do so will result in errors starting Podman as the number of locks available conflicts with the configured number of locks.

**podman system renumber** can also be used to migrate 1.0 and earlier versions of Podman, which used a different locking scheme, to the new locking model. It is not strictly required to do this, but it is highly recommended to do so as deadlocks can occur otherwise.

If possible, avoid calling **podman system renumber** while there are other Podman processes running.

## SEE ALSO
`podman(1)`, `libpod.conf(5)`

## HISTORY
February 2019, Originally compiled by Matt Heon (mheon at redhat dot com)
