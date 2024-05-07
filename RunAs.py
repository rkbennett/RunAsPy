import argparse
import RunAsPy

parser = argparse.ArgumentParser(description="")
parser.add_argument('-d', '--domain', help="", nargs="?", dest="domainName")
parser.add_argument('-u', '--username', help="", nargs="?")
parser.add_argument('-P', '--password', help="", nargs="?")
parser.add_argument('-c', '--command', help="", nargs="*", dest="cmd")
parser.add_argument('-t', '--timeout', help="", nargs="?", default=120000, dest="processTimeout", type=int)
parser.add_argument('-l', '--logon-type', help="", nargs="?", default=2, dest="logonType", type=int, choices=[2, 3, 4, 5, 8, 9])
parser.add_argument('-f', '--function', help="", nargs="?", dest="createProcessFunction", default=RunAsPy.DefaultCreateProcessFunction(), type=int)
parser.add_argument('-r', '--remote', help="", nargs="?", default=None)
parser.add_argument('-p', '--force-profile', help="", action="store_true", default=False, dest="forceUserProfileCreation")
parser.add_argument('-b', '--bypass-uac', help="", action="store_true", default=False, dest="bypassUac")
parser.add_argument('-i', '--remote-impersonation', help="", action="store_true", default=False, dest="remoteImpersonation")
parser.add_argument('-v', '--verbose', help="increase verbosity", action="store_true")

args = parser.parse_args()

if args.remote:
    args.processTimeout = 0

print(RunAsPy.Runas(**args.__dict__))