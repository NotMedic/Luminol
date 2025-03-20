### Luminol

I've named this script “Luminol” because it helps us find things BloodHound can’t find. 

Luminol is designed to be added as a scheduled task via Group Policy. 

When the script runs, the computer does a minimized collection on itself and generates a JSON document that can be ingested into neo4j using the existing BloodHound pipeline. 

Luminol provides a significant amount of opportunity to gather information for attack path generation since it runs as SYSTEM on the box itself, giving additional visibility network-based collection can't see. 

Luminol does not require ACL changes for SAMR or NetSessionEnum, and also does not require line-of-sight from SharpHound, meaning network segmentation or host-based firewalls shouldn’t get in the way. The endpoint doesn’t have to be online when SharpHound is ran.

Since Session information is focused on “who is logged in from where," we can identify where credentials would be exposed that could be abused by an attacker, we wanted to explore places where we could pull that information from the system itself. 

The current methodology probably covers 90+% of credential exposure by pulling these items:
* Processes and the account they’re running as

   If a user has a process running on a box, that process token can be stolen and allow for user impersonation, even is the system has been hardened against LSASS theft. This also means that there are likely credentials such as kerberos tickets, NTHashes, or clear-text credentials in memory. 
* Windows Services and the account they’re running as

   Windows Service credentials are stored in the registry and can be recovered by an attacker with administrative privileges. 
* Scheduled Tasks and the account they’re scheduled to run as

   Scheduled Task “runas” credentials are stored in the registry and can be recovered by an attacker with administrative privileges.
* Luminol also gathers local group memberships for privileged groups that have remote access, such as Administrators and Remote Desktop Users. This allows us to gather this information even if an endpoint is running Windows 10 > 1607 or has had SAMR hardened against network-based enumeration. 
 
 
Bloodhound’s network-based, low-privileged enumeration cannot identify these at-risk credentials since the tool was designed for attackers who have gained a low-privileged foothold within an AD Domain to find paths to higher privileges. This isn’t a fault of BloodHound, but a design decision based on different use cases.
