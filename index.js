import express, {json} from "express";
import bcrypt from "bcryptjs";
import prisma from "./src/db.js";
import crypto, {hash} from "crypto";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

app.use(cors({origin: 'https://viniwebsite.vercel.app/', credentials: true}));
app.use(express.json());
app.use(cookieParser());

async function verifyToken(req, res, next){
    const cookieHeader = req.cookies.auth;

    if (!cookieHeader) {
      req.authCookies = null;
      next();
      return;
    }

        req.authCookies = cookieHeader;
        next();
}

app.get('/', async(req, res) => {

    res.send('Welcome');
})

app.get('/getUser', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await prisma.user.findMany({
            where: {
                email: {equals : email},
                password: {equals : password}
            }
        })

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if(!isPasswordValid) {
            res.status(401).send({"Password is incorrect": false});
        }

        res.json(user.name)

    }catch (e) {
        res.status(400).send({error: e});
    }

})

app.post('/register', async(req, res) => {
   const  { name, email, password} = req.body;

   const salt = await bcrypt.genSalt(2);
   const hash = await bcrypt.hash(password, salt);

   try{
        const userCreated = await prisma.user.create({
           data:{
               name: name,
               email: email,
               password: hash
           }
       });

     const token = await crypto.randomBytes(16).toString("hex");

     await prisma.session.create({
       data: {
         token: token,
         userId: userCreated.id,
         created_at: new Date(),
         updated_at: new Date(),
         expire_at: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
       }
     });

     res.cookie('auth', token);
     res.json(userCreated);

   } catch(err){
       res.status(500).send({error: err.message || 'Erro ao criar usuário'});
   }
});

app.post('/login', verifyToken, async(req, res) => {
    const {email, password} = req.body;
    const cookieAuth = req.authCookies;

    try {
          if(cookieAuth) {
            const session = await prisma.session.findUnique({
              where: {token: cookieAuth},
            })

            if(session) {
              const userExist = await prisma.user.findUnique({
                where: {id : session.userId},
              })

              if(userExist){
                res.status(201).json(userExist);
                return
              }
            }

          }

            const user = await prisma.User.findUnique({
                where: {
                    email: email
                }
            });

            if(!user){
                res.status(400).json("Usuario nao existe");
                return
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);

            if(!isPasswordValid){
                res.json('400').json({error: 'Incorrect password.'});
                return
            }

            const token = await crypto.randomBytes(16).toString("hex");

            await prisma.session.create({
                            data: {
                                token: token,
                                userId: user.id,
                                created_at: new Date(),
                                updated_at: new Date(),
                                expire_at: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
                            }
                        });

                res.cookie('auth', token);
                res.json(user);

    }catch(err){
        console.log(err);
    }
})

app.patch('/update', verifyToken, async(req, res) => {
  const cookieAuth = req.authCookies;
  const {name, email} = req.body;

  try {
    if(cookieAuth) {
      const sessionExist = await prisma.session.findUnique({
        where: {token : cookieAuth},
      })

      if(sessionExist) {
         await prisma.user.update({
          where: {
            email: email
          },
          data : {
            name : name,
            email : email
          }
        })

        res.json(201);
         return
      }
      res.json(401)
    }
  }catch (e) {
    res.status(400).send({error: e});
  }
})

app.delete('/delete', verifyToken, async(req, res) => {
  const cookieAuth = req.authCookies;
  const {email} = req.body;

  console.log(cookieAuth);
  console.log(email);

  try {
    if(cookieAuth) {
      const sessionExist = await prisma.session.findUnique({
        where: {token : cookieAuth},
      })

      if(sessionExist) {
       await prisma.user.delete({
          where: {
            email: email
          }
        })

        res.json(201);
      }
      res.json(401)
    }
  }catch (e) {
    res.status(400).send({error: e});
  }
})

app.listen(8080);