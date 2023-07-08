const express = require('express');
const app = express();
const port = 4200;

const sites={
    0:'http://localhost/moodle414',
    1:'https://dcert.kku.ac.th',
    2:'https://x.kku.ac.th',
    3:'https://click.kku.ac.th',
};

app.get('/auth/thaid-call-back', (req, res) => {
    const u = new URLSearchParams(req.query).toString();
    console.log(req.query,u);
    let num = req.query.state.charAt(0);
    res.redirect(`${sites[num]}/auth/thaid/callback.php?`+u);
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
})
