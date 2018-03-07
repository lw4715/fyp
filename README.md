# Execute a query
Start SICStus:
```sh
$ cd src
$ sicstus
```
To query for culprit for an attack, replace `attack` with one of the following: `us_bank_hack, apt1, gaussattack, stuxnetattack, sonyhack, wannacryattack`

To query for a specific group/country, replace `Culprit` with a country (all lower case) e.g. `northkorea` or a group (camel case) e.g. `lazarusGrp`.
```prolog
?- [tech_rules].
?- goal(attack, X, D1, D2, D3, D4, D5).
?- [op_rules].
?- goal(attack, X, D1, D2, D2).
?- [str_rules].
?- prove([isCulprit(Culprit, attack)], D).
```
# Main files in src folder:
* tech_rules.pl : technical rules
* op_rules.pl : operational rules
* str_rules.pl : strategic rules
* tech.pl : written by tech_rules.pl, used by both op_rules.pl and str_rules.pl
* op.pl : written by op_rules.pl, used by str_rules.pl

# Link to report
[Report on overleaf](https://www.overleaf.com/read/ytjpcsksccny)
