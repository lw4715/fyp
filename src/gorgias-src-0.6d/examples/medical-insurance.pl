% =============================================================== %
%                      MEDICAL INSURANCE EXAMPLE		  %	
% =============================================================== %
% This example is taken from the paper 'Inheritance Comes of 	  %
% Age: Applying Nonmonotonic Techniques to Problems in Industry'  %
% by Leora Morgenstern. It is used here to illustrate use of 	  %
% preference rules in inheritance problems.	 		  %			    
% =============================================================== % 

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


rule(r1(X), covers_surgical_benefit(X),      [surgical(X)]).
rule(r2(X), surgical(X),                     [endoscopic(X)]).
rule(r3(X), surgical(X),                     [orthopedic(X)]).
rule(r4(X), surgical(X),                     [maternity_surgical(X)]).
rule(r5(X), endoscopic(X),                   [routine_endoscopy(X)]).
rule(r6(X), endoscopic(X),                   [sickness_endoscopy(X)]).
rule(r7(X), covers_maternity_benefit(X),     [maternity(X)]).
rule(r8(X), maternity(X),                    [maternity_surgical(X)]).
rule(r9(X), neg(covers_surgical_benefit(X)), [routine_endoscopy(X)]).

rule(f1,    routine_endoscopy(re1),          []).
rule(f2,    sickness_endoscopy(se1),         []).
rule(f3,    maternity_surgical(ms1),         []).
rule(f4,    orthopedic(o1),                  []).

rule(pr,    prefer(r9(X), r1(X)),            []).

% =============================================================== % 
       



