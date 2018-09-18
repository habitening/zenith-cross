zenith-cross
############

zenith-cross is the foundation for an application that uses federated
login on Google App Engine. It contains webapp2 handlers and helpers
that use identity providers like Facebook, GitHub, Google, LinkedIn, and
Twitter to authenticate a user. Basically, it is a tested implementation of the
OAuth dance. Despite the chorus of people saying it is trivial, it actually
takes some work to get right.

When Google stopped supporting federated login on App Engine, it left Google as
the only identity provider for App Engine. If you want to use federated login,
then you have to build a client single page app with Firebase login. This
stores the login credentails on the client-side and, MOST ALARMING for me,
exposes my secret keys. In addition, it is a hassle on the server side because
I have to build and support a full API around the JSON Web Token (JWT) Firebase
uses when I just wanted a simple login.

If you are looking to store your own username/password, **THIS IS NOT**
the code for you. But before you move on, please let me try to convince you
to use federated login.

Why no username/password?
-------------------------

There are too many username/password systems in the world. Each of these sites
has one because they think they are going to be the next Facebook or Twitter.
**YOU ARE NOT SPECIAL. YOU ARE NOT UNIQUE.**

This puts a burden on users to come up with a memorable but unique
username/password combination. This is hard and people just end up
using the same password for every site. And when one site is compromised, the
attacker has access to the user's accounts on all the other sites. You can
add character and length requirements to try to get unique passwords but if
these requirements become too onerous, then visitors may simply leave.

The old line of "why do people rob banks? Because that's where the money is"
applies here. Once you store passwords, you have something of value and you are
stuck in an ever escalating war of resources against bad guys to protect these
passwords. Can you afford to spend this time and money?

At this point, you may be saying that you have taken all the necessary security
precautions to make sure this would never happen like
- making sure passwords are never stored in plain text
- making sure passwords never leak into your logs
- passwords are salted and hashed

This may well be true
- But are you sure everybody else is doing this?
- Are you sure you don't have a disgruntled or a financially motivated employee
  who can compromise your system or simply walk away with the information?

With federated login, the user no longer has to think of a username/password
combination for your site if they already have an account with an identity
provider. This reduces the burden of login to them. And you get to outsource
protecting passwords to the identity providers who are bigger and better
funded. It is a win-win for both sides of login.

Dependencies
------------

zenith-cross only requires `the included third-party libraries in App Engine
<https://cloud.google.com/appengine/docs/standard/python/tools/built-in-libraries-27>`_,
in particular
- jinja2
- webob
- webapp2
- yaml

The application is designed to require as few libraries as possible.
