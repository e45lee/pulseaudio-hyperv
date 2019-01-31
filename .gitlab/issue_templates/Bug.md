<!---
Please read this!

Before opening a new issue, make sure to search for keywords in the issues
filtered by the "regression" or "bug" label.

For the Community Edition issue tracker:

- https://gitlab.com/gitlab-org/gitlab-ce/issues?label_name%5B%5D=regression
- https://gitlab.com/gitlab-org/gitlab-ce/issues?label_name%5B%5D=bug

For the Enterprise Edition issue tracker:

- https://gitlab.com/gitlab-org/gitlab-ee/issues?label_name%5B%5D=regression
- https://gitlab.com/gitlab-org/gitlab-ee/issues?label_name%5B%5D=bug

and verify the issue you're about to submit isn't a duplicate.
--->


WARNING: Missing data may cause bugs to languish.  
Unless you are sure its not relevant please attach files for each command under the environment heading. 
 
  
environment:  
	`uname -a`  
	`aplay -l`  
	`arecord -l`    
	`pactl info`  
	`pactl list`  
	`pulseaudio --version`  
  
steps to reproduce:  
  
expected behaviour:  
  
observed behaviour: 


Take the useful bits from this file:
  https://gitlab.com/gitlab-org/gitlab-ce/raw/master/.gitlab/issue_templates/Bug.md
  The formatting and instructions are nicer in that file, but it
  contains some useless stuff. The useful bits, in my opinion, are
  the "Summary", "Steps to reproduce", "What is the current *bug*
  behavior?" and "What is the expected *correct* behavior?"
  sections.
  
  
