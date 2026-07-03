##FAILURES OF PRIVACY FILTER
Privacy Filter can make mistakes, such as: under-detection of uncommon personal
names, regional naming conventions, initials, honorific-heavy references, or domain-specific identifiers; over-redaction of public entities, locations, or common nouns when local context is ambiguous;
fragmented or shifted span boundaries in mixed-format text, long documents, or text with heavy
punctuation and layout artifacts; missed secrets for novel credential formats, project-specific token patterns, or secrets split across surrounding syntax; and over-redaction of benign high-entropy
strings, placeholders, hashes, sample credentials, or synthetic examples that resemble secrets.

Show this using custom datasets.



There can be a way to recover some information from text file with redcated tokens.

In all evaluation tests in the case of failed or adverserial examples, leaking of one private information can allow attackers to get information on other redacted tokens and identity using linkage or contextual understanding in the paragraph.


Assume we will have a data set with [ account_number | private_address | private_date | private_email | private_person | private_phone | private_url | secret ] these in a table, so if privacy filter leaks any one of this items, we can fill in the rest of the items by guesses from attackers, if i know the addres or the number than i know other details in the table to , all are one to one mapping onto individuals. Now using contextual information even one leak at one place can help attacker revert the entire document back to orignal with high accuracy. Claiming the privacy protection showed by precision and recall are not a good metric and even one leak can cause more identification of individuals, 
currently trading precision and recall can you help you in more protection but the claim is scrubbing doesnt give you 100 percent protection and 98 percent recall is also not good enough and how this metric is  biased.

there can be conjectures and links in the text file itself, for example if mr x and mr y are neighbours, if the dataset has only one neighbour for x which is in the dataset, revealing mr x identity also reveals mr y's. 

for things like time and other details which are not one to one mapping the attacker agent will have some estimate about the time and the details, we can  evaluate by how close our guess is for time, for ex if time duration between two timestep is known due to conversation/context we can have better guesses. 

