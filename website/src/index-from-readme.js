fs = require('fs');

fs.readFile("../README.md", function (err, buf) {
  if (err) return console.log(err);
  var readme_without_img = buf.toString().replace('website/static/', '');
  var content =
    `---
slug: "/"
title: "bash-helpers"
hide_title: true
---
${readme_without_img}`
  fs.writeFile('./src/pages/index.md', content, function (err) {
    if (err) return console.log(err);
  });
});