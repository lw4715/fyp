%% wannacry
%% rules
isCulprit(X, A1) :- similarNature(A1, A2), isCulprit(X, A2).

%% evidence
similarNature(wannacryattack, ).
malwareUsedInAttack(wannacry, wannacryAttack).
target(nhs, wannacryattack).
neg(specificTarget(wannacryattack)). % more than 100 countries affected

hasKillSwitch(wannacry).
type(wannacry, ransomware). % TODO: diff types of malware
propagationMechanism(wannacry, self_propagating).
scale(wannacryattack, large).
exploitVul('EternalBlue'). % microsoft SMB protocol
vulPatched('EternalBlue'). % MS17-010
vulReleased('EternalBlue', 14, 4, 17). % released by Shadow Brokers on 14/4/17
dateOfAttack(12, 5, 17, wannacryattack).
ccCommunicationChannel(tor).

%% https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html