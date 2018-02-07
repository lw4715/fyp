%% Demonstrates punctual behavior

:- compile('../sv').

:- multifile action/4, goal/3, failed/1.


title('TEST 1').
comment('Same scenario, different profile. Note that a PUNCTUAL computee prefers to execute an action that is urgent (see h_u_AS) while a CAREFUL computee prefers a PR transition since there are timeout actions. Moreover, the impatient computee prefers to do anything else beside an action execution (h_fail_AS) and focused executes an action from the same plan as the previous action.').



computee :: {

     super(computee_basic) &

     attributes([timepoint(5)]) &

     history(0,step('INIT',[])) &

     history(1,step('PO',[])) &

     history(2,step('GI',[])) &

     history(3,step('PI',[])) &

     history(4,step('AE',[action(call_taxi,g2,[],4)]))

}.

goal(hotel_checkout,nil,10).
goal(hotel_payment,hotel_checkout,9).

action(ccvs_connect,hotel_payment,[],1).
action(ccvs_mk_payment,hotel_payment,[],2).
action(notify_hotel_about_payment,hotel_payment,[],3).
action(call_taxi,hotel_checkout,[],4).
action(request_porter,hotel_checkout,[],5).

failed(call_taxi).

:- start.
