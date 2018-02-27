%xcel example:
% consider source of evidence (ip addr)
%hids: Host-based intrusion detection system
%possible sources: ssh_sys_log, hids, firewall, wireshark, dns, reversing

% Question:
% How to detect TOR connections??

% helper functions
split([46|S], L, S).
split([X|S], [X|L], R) :- split(S, L, R).

% domain(IP, D). % use DNS
isInternalIP(IP) :- (split(IP, "192", T), split(T, "168", IP));
  (concatenate("172", "16", H), concatenate(H, _, IP));
  (concatenate("10", _, H), concatenate(H, _, IP)).

similarIPSubnet(IP1, IP2) :- concatenate(A1, A2, H1), concatenate(A1, A2, H2), concatenate(H1, _, IP1), concatenate(H2, _, IP2).


isCulprit(TG, Att) :- malwareUsedInAttack(M, Att), iocMatched(M, IOC), iocThreatGroup(IOC, TG).
motive(C, Att) :- malwareUsedInAttack(M, Att), iocMatched(M, IOC), iocThreatCategory(IOC, Cat).
not isCulprit(X, Att) :- attackIncludes(X, Att).


similarStrategy(A1, A2) :- useZeroDayVul(A1), useZeroDayVul(A1).
% strategy: target, zeroday or not, social engineering, iocs


notes:
% public iocs
% https://github.com/fireeye/iocs


% malwareInstallationSource(IP, M), spoofedIp(IP, Att), malwareUsedInAttack(M, Att).
