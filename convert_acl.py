#!/usr/bin/env python3
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import os
import subprocess
import shlex
import sys
import threading

from tree_walk import Callback
from tree_walk import ParallelTreeWalk

"""
Converts ACLs of directories if ALL of the following criterias match:
  - there is at least one ACE that sets inheritance for a non-special
    principal
  - there is no ACE that sets inheritance for any special principal
  - there is exactly one allow ACE for each special principal
  - there is no deny ACE for any special principal

Directories will be ignored if:
  - there is no ACE that sets inheritance
  - there is at least one ACE that sets inheritance for each special principal

The result of the conversion will be as follows:
  - all ACEs are copied
  - one ACE for each special principal is added with an added INHERIT_ONLY
    flag copying the permissions of the existing ACE of the principal

Example:
  A::OWNER@:rwaDxtnNcy
  A:g:GROUP@:rxtncy
  A:g:EVERYONE@:rxtncy
  A:fdg:readers:rxtncy
  A:fdg:writers:rwaDxtTnNcCy

will be converted into
  A::OWNER@:rwaDxtnNcy
  A:g:GROUP@:rxtncy
  A:g:EVERYONE@:rxtncy
  A:fdg:readers:rxtncy
  A:fdg:writers:rwaDxtTnNcCy
  A:fdi:OWNER@:rwaDxtnNcy
  A:fdig:GROUP@:rxtncy
  A:fdig:EVERYONE@:rxtncy

"""
__copyright__ = "Copyright 2022, Quobyte Inc"


SPECIAL_PRINCIPALS = ["OWNER@", "GROUP@", "EVERYONE@"]


class TextAce:
    """ Represents a single line of a nfs4_getacl output """
    def __init__(self, string: str) -> None:
        data = string.split(":")
        assert len(data) == 4
        self._type = data[0]
        self._flags = data[1]
        self._principal = data[2]
        self._permissions = data[3]

    def hasInheritanceFlag(self) -> bool:
        return any(flag in self._flags for flag in ['i', 'f', 'd'])

    def hasSpecialPrincipal(self) -> bool:
        for principal in SPECIAL_PRINCIPALS:
            if self._principal == principal:
                return True
        return False

    def getType(self) -> str:
        return self._type

    def getFlags(self) -> str:
        return self._flags

    def getPrincipal(self) -> str:
        return self._principal

    def getPermissions(self) -> str:
        return self._permissions

    def isAllowAce(self) -> bool:
        return self._type == "A"

    def isDenyAce(self) -> bool:
        return self._type == "D"

    def toString(self) -> str:
        return "{}:{}:{}:{}{}".format(
            self._type, self._flags, self._principal, self._permissions,
            os.linesep)


class Acl:
    """
    Stores the output of nfs4_getacl as individual ACEs and does the
    conversion
    """
    def __init__(self, string: str) -> None:
        self._aces = []
        self._added_aces = []

        for line in string.split(os.linesep):
            if (len(line) == 0):
                continue
            if line[0] == "#":
                continue
            self._aces.append(TextAce(line))

    def convert(self) -> bool:
        """
          Returns
            true  if the ACL was converted
            false if there was no need to convert the ACL

          An exception is raised if the ACL cannot be converted
        """

        #  - there is at least one ACE that sets inheritance for a non-special
        #    principal
        if sum(1 for ace in self._aces if ace.hasInheritanceFlag()) == 0:
            return False

        #  - there is no ACE that sets inheritance for any special principal
        num_aces = 0
        for principal in SPECIAL_PRINCIPALS:
            if sum(1 for ace in self._aces
                   if ace.hasInheritanceFlag() and
                   ace.getPrincipal() == principal) > 0:
                num_aces = num_aces + 1

        if num_aces == len(SPECIAL_PRINCIPALS):
            # there are ACEs with inheritance for all special principals
            return False

        if num_aces > 0:
            raise RuntimeError("Cannot convert ACL as inheritance is not set "
                               "for all special principals")

        #  - there is exactly one allow ACE for each special principal
        #  - there is no deny ACE for any special principal
        for principal in SPECIAL_PRINCIPALS:
            num_allow_aces = sum(1 for ace in self._aces
                                 if ace.getPrincipal() == principal and
                                 ace.isAllowAce() and not
                                 ace.hasInheritanceFlag())
            num_deny_aces = sum(1 for ace in self._aces
                                if ace.getPrincipal() == principal and
                                ace.isDenyAce() and not
                                ace.hasInheritanceFlag())
            if num_allow_aces > 1 or num_deny_aces > 1:
                raise RuntimeError(
                    "Cannot convert ACL as there are too many rules for "
                    "principal {} ".format(principal))

        for ace in self._aces:
            if ace.isAllowAce() and ace.hasSpecialPrincipal():
                new_ace = TextAce("{}:fdi{}:{}:{}".format(
                    ace.getType(),
                    ace.getFlags(),
                    ace.getPrincipal(),
                    ace.getPermissions()))
                self._added_aces.append(new_ace)
        return True

    def toString(self) -> str:
        result = ""
        for ace in self._aces:
            result += ace.toString()
        for ace in self._added_aces:
            result += ace.toString()
        return result


"""
Fetches the ACL via nfs4_getacl converts and maybe writes the result back.
Acts as callback to the tree walk.
"""


class AclConverter(Callback):
    def __init__(self, options) -> None:
        super().__init__()
        self._options = options
        self._lock = threading.Lock()

    def processEntry(self, path: str) -> bool:
        try:
            if not os.path.islink(path) and os.path.isdir(path):
                self._processDirectory(path)
                return True
        except Exception as ex:
            self.callOnError(path, ex)
            pass
        return False

    def _processDirectory(self, path: str):
        # get the ACL
        get_out = subprocess.run(
            shlex.split("nfs4_getfacl {}".format(path)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if get_out.returncode != 0:
            self.callOnError(path, "Failed to run nfs4_getfacl: {}".format(
                get_out.stderr.decode().strip()))
            return

        # convert it
        acl = Acl(get_out.stdout.decode())
        if not acl.convert():
            return

        if self._options.dry_run:
            self._logMessage("{}{}{}".format(path, os.linesep, acl.toString()))
            return

        # write back the converted result
        set_out = subprocess.run(
            f'echo "{acl.toString()}" | nfs4_setfacl -S - {path}',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        if set_out.returncode != 0:
            self.callOnError(path, "Failed to run nfs4_setfacl: {}".format(
                set_out.stderr.decode().strip()))
            return

    def _logMessage(self, message: str) -> None:
        self._lock.acquire()
        print(message)
        self._lock.release()

    def _logError(self, message: str) -> None:
        self._lock.acquire()
        print(message, file=sys.stderr)
        self._lock.release()

    def callOnError(self, path: str, exception: Exception):
        self.callOnError(path, str(exception))

    def callOnError(self, path: str, error: str):
        self._logError("Failed to process {}: {}".format(path, error))


if __name__ == '__main__':
    parser = ArgumentParser(
        description='Quobyte ACL converter',
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("directory")
    parser.add_argument('--num-threads',
                        default=30,
                        help='Number of threads for the parallel tree walk')
    parser.add_argument('--dry_run',
                        action='store_true',
                        help='Do not modify files but print the resulting ACL')
    options = parser.parse_args()

    walk = ParallelTreeWalk(options.num_threads, AclConverter(options))
    walk.run(options.directory)
