//================================================================================ [공통] Express 라이브러리 import
const express = require('express');
const { Console, info } = require('console');

//================================================================================ [공통] dotenv 환경변수 등록
require('dotenv').config({ path:'./secrets/.env'})

//================================================================================ [공통] react router 관련 라이브러리 import
const path = require('path');

//================================================================================ [공통] passport 라이브러리 import
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');

//================================================================================ [공통] body-parser 라이브러리 import
const bodyParser= require('body-parser')
//================================================================================ [공통] connect-flash 라이브러리 import
const flash= require('connect-flash')

//================================================================================ [공통] axios AJAX 라이브러리 import
const { default: axios } = require('axios');

//================================================================================ [공통] maria DB 라이브러리 import
const {strFunc, insertFunc, batchInsertFunc, batchInsertOnDupliFunc, whereClause, truncateTable} = require ('./maria_db/mariadb');
const { type } = require('os');

//================================================================================ [공통] bcrypt 라이브러리 import
const bcrypt = require('bcrypt');
const saltRounds = 1;

//================================================================================ [공통] jwt 라이브러리 import
const jwt = require("jsonwebtoken");

//================================================================================ [공통] Express 객체 생성
const app = express();

//================================================================================ [공통 미들웨어] json
app.use(express.json({limit: '10mb'}))
//================================================================================ [공통 미들웨어] body-parser
app.use(bodyParser.urlencoded({extended: true})) 
app.use(express.urlencoded({limit: '10mb', extended: true}))
//================================================================================ [공통 미들웨어] connect-flash
app.use(flash())

//================================================================================ [공통 미들웨어] passport
const expireTimeMinutes=10
app.use(session({secret : process.env.passport_secret_code, resave : false, saveUninitialized: false, cookie: { maxAge : expireTimeMinutes*60000 }, rolling:true})); //cookie: { maxAge : 60000 } 제외함
app.use(passport.initialize());
app.use(passport.session());
//================================================================================ [공통 미들웨어] react router 관련
app.use(express.static(path.join(__dirname, process.env.react_build_path)));

//================================================================================ [공통 기능] 서버실행
app.listen(process.env.PORT, function() {
    console.log('listening on '+ process.env.PORT)
  })

  //================================================================================ [공통 기능] 로그인 증명
app.post('/login', passport.authenticate('local', {successRedirect :"/logincheck",failureRedirect : '/fail', failureFlash : true}), function(req, res){
    res.redirect('/')
  });
  
  app.get('/logout', loginCheck,function(req,res){
    req.session.destroy(async() =>
    {
      res.clearCookie('connect.sid');

      let auditTrailRows=[]
      auditTrailRows.push([req.user.user_account,"로그아웃",""])
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

      res.redirect('/');
      
    });
  })

  app.get('/fail', function(req,res){ //수정중
    res.json({success : false, flashMsg : req.session.flash.error.slice(-1)[0]})
    console.log(req.session.flash.error)
  })
  
  app.get('/logincheck', loginCheck, function (req, res) {
    res.status(200).json({success : true, userInfo : req.user, expireTime:expireTimeMinutes})
  }) 
  
  function loginCheck(req, res, next) { 
    if (req.user) {
      next()
    } 
    else {
      res.json({success : false})
    } 
  } 
  
  passport.use(new LocalStrategy({
    usernameField: 'id',
    passwordField: 'pw',
    session: true,
    passReqToCallback: false,
  }, function (reqID, reqPW, done) {
    console.log("verifying user account ...")
    strFunc("SELECT * FROM tb_user WHERE user_account='"+reqID+"'")
      .then(async (rowResult)=>{
        if (rowResult.length<1)
        {
          console.log("This account is not exist")

          let auditTrailRows=[]
          auditTrailRows.push([reqID,"존재하지 않은 계정 '"+reqID+"'으로 로그인 시도",""])
          await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

          return done(null, false, { message: "no user_account" })
        }
        if (rowResult.length==1)
        {
          strFunc("SELECT * FROM tb_user_auth WHERE user_account='"+reqID+"'")
          .then(async (authResult)=>{
            if(authResult.length<1){
              console.log("This account is unvalid")

              let auditTrailRows=[]
              auditTrailRows.push([reqID,"권한이 없는 계정 '"+reqID+"'으로 로그인 시도",""])
              await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

              return done(null, false, { message: 'no auth' })
            }
            else{
              if (bcrypt.compareSync(reqPW, rowResult[0].user_pw))
              {
                console.log("This account and PW was verified")

                let auditTrailRows=[]
                auditTrailRows.push([reqID,"로그인",""])
                await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

                return done(null, rowResult)
              }
              else
              {
                console.log("This account is valid but this PW is wrong.")

                let auditTrailRows=[]
                auditTrailRows.push([reqID,"로그인 실패 (잘못된 패스워드)",""])
                await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

                return done(null, false, { message: 'wrong PW' })
              }
            }
          })
        }
      })
  }));
  
  passport.serializeUser(function (rowResult, done) {
    done(null,rowResult[0].user_account)
    console.log("Session was created.")
  });
  
  passport.deserializeUser(function (user_id, done) {
    strFunc("SELECT tb_user.user_account as user_account, tb_user.user_name as user_name, tb_user_auth.user_auth as user_auth FROM tb_user LEFT OUTER JOIN tb_user_auth ON tb_user.user_account = tb_user_auth.user_account WHERE tb_user.user_account='"+user_id+"'")
    .then((rowResult)=>{
  
      let user_auths = []
  
      rowResult.map((oneRow,i)=>{
        user_auths.push(oneRow.user_auth)
      })

      done(null, {
        user_account:rowResult[0].user_account,
        user_name:rowResult[0].user_name,
        user_auth:user_auths,
        secret_data : jwt.sign({data:"nothing"}, process.env.jwt_secret_key)
      })
    })
  
  });
  //================================================================================ [공통 기능] jwt 복호화 (개발중)
  app.get('/jwtverify', loginCheck, function(req,res){
    console.log(req.query)
    console.log(jwt.verify(req.query.token,  process.env.jwt_secret_key))
    res.json(jwt.verify(req.query.token,  process.env.jwt_secret_key))
  })

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getaudittrail', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT user_account, user_action, data, BIN_TO_UUID(uuid_binary) AS uuid_binary, action_datetime FROM tb_audit_trail " + await whereClause("tb_audit_trail",req.query.searchKeyWord) +" ORDER BY action_datetime DESC")
    .then((rowResult)=>{
      return {success:true, result:rowResult}})
    .catch((err)=>{
      return {success:false, result:err}})
    res.json(qryResult)
  });


  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getmypage', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary FROM tb_user WHERE user_account ='"+req.query.user_account+"'")
    .then((rowResult)=>{
      return {success:true, result:rowResult}})
    .catch((err)=>{
      return {success:false, result:err}})
    res.json(qryResult)
  });


  //================================================================================ [공통 기능] 계정 생성
    app.post('/postaddaccount', loginCheck, async function(req,res){
      let insertTable="tb_user";
      let columNamesArr=[]
      let questions=[]
      let valueArrys=[]
      let hashedPw= await bcryptHashing(req.body["user_pw"])

      Object.keys(req.body).map(async (keyName,i)=>{
        if(keyName=="user_pw"){
          columNamesArr.push(keyName)
          questions.push('?')
          valueArrys.push(hashedPw)
        }
        else{
          columNamesArr.push(keyName)
          questions.push('?')
          valueArrys.push(req.body[keyName])
        }

      })

      columNamesArr.push("insert_datetime")
      questions.push('now()')

      columNamesArr.push("uuid_binary")
      questions.push('UUID_TO_BIN(UUID())')

      let auditTrailRows=[]
      auditTrailRows.push(req.body.insert_by,"'" + req.body.user_account + "' 계정 생성",req.body.user_account)

      let qryResult = await insertFunc(insertTable,columNamesArr,questions,valueArrys)
      .then(async (rowResult)=>{
        await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:rowResult}
      })
      .catch((err)=>{return {success:false, result:err}})
      
      res.json(qryResult)
    })

    async function bcryptHashing(plainPW){
      let hashedPw = await bcrypt.hash(plainPW, saltRounds)
      return hashedPw
    }
    
  //================================================================================ [공통 기능] 계정 정보 수정
  app.put('/putediteaccount',loginCheck,async function(req,res){
    let auditTrailDataBefore= await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email,user_phone, remark FROM tb_user WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
    let auditTrailDataAfter=[]
    let auditTrailRows=[]

    let setArrys=[]

    Object.keys(req.body).map(async (keyName,i)=>{
      if(keyName=="uuid_binary"){ 
        // uuid는 업데이트할 Row 검색 조건이기 때문에 변경 안 함
      }
      else if(keyName=="user_account"){
        // user_account는 PK이기 때문에 변경 안 함
      }
      else if(keyName=="user_pw"){
        // PW 변경은 별도 기능에서 다룰 것이기 때문에 변경 안 함
      }
      else{
        if(typeof(req.body[keyName])=="string") setArrys.push(keyName+"='"+req.body[keyName]+"'")
        else if(typeof(req.body[keyName])=="number") setArrys.push(keyName+"="+req.body[keyName]+"")
      }
    })

    setArrys.push("update_datetime=now()")

    let qryResult = await strFunc("UPDATE tb_user SET "+ setArrys.join(",") + " WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
    .then(async (rowResult)=>{
      auditTrailDataAfter = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email,user_phone, remark FROM tb_user WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
      
      auditTrailRows.push(req.body.update_by,"'" + req.body.user_account + "' 계정의 정보수정", JSON.stringify({Before:auditTrailDataBefore,After:auditTrailDataAfter}))
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

      return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

    //================================================================================ [공통 기능] 비밀번호 수정 (uuid_binary, user_account, 변경할 pw, 받아야함)
    app.put('/resetaccountpw',loginCheck,async function(req,res){
      let setArrys=[]
      let hasedPw = await bcryptHashing(req.body.user_pw)
      
      setArrys.push("user_pw='"+hasedPw+"'")
      setArrys.push("update_datetime=now()")

      let auditTrailRows=[]
      auditTrailRows.push(req.body.reset_by,"'" + req.body.user_account + "' 계정의 비밀번호 수정",req.body.user_account)

      let qryResult = await strFunc("UPDATE tb_user SET "+ setArrys.join(",") + " WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
      .then(async (rowResult)=>{
        await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:rowResult}
      })
      .catch((err)=>{return {success:false, result:err}})
      res.json(qryResult)
   
    })

    //================================================================================ [공통 기능] 비밀번호 수정 (before_user_pw, after_user_pw, user_account, update_by 받아야함 (이론적으로 update_by, user_account가 동일할 것 (mypage이기 때문)
    app.put('/changepwself',loginCheck,async function(req,res){
      let currentPwRow = await strFunc("SELECT user_pw FROM tb_user where user_account = '" + req.body.user_account + "'")
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})

      if(currentPwRow.result.length=1){
        if(bcrypt.compareSync(req.body.before_user_pw, currentPwRow.result[0].user_pw)){

          let hasedPw = await bcryptHashing(req.body.after_user_pw)

          let setArrys=[]
          setArrys.push("user_pw='"+hasedPw+"'")
          setArrys.push("update_datetime=now()")

          let qryResult = await strFunc("UPDATE tb_user SET "+ setArrys.join(",") + " where user_account = '" + req.body.user_account + "'")
          .then(async (rowResult)=>{
            return {success:true, result:rowResult}
          })
          .catch((err)=>{return {success:false, result:err}})

          if(qryResult.success){
            let auditTrailRows=[]
            auditTrailRows.push(req.body.update_by,"My Page에서 자신의 계정 '" + req.body.user_account + "'의 비밀번호 수정",req.body.user_account)
            await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
          }

          res.json(qryResult)
        }
        else{
          res.json({success:false, result:"현재 패스워드가 일치하지 않습니다."})
        }      
      }
      else{
        res.json({success:false, result:"유일한 계정이 확인되지 않습니다."})
      }
    })

  //================================================================================ [공통 기능] 계정 삭제 [on Audit Trail]
    app.delete('/deleteaccount',loginCheck,async function(req,res){
      let auditTrailRows=[]
      auditTrailRows.push(req.query.delete_by,"계정 '" + req.query.user_account + "' 삭제",req.query.user_account)

      let qryResult = await strFunc("DELETE FROM tb_user WHERE uuid_binary = UUID_TO_BIN('" + req.query.uuid_binary +"')")
      .then(async (rowResult)=>{
        await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:rowResult}
      })
      .catch((err)=>{
        if (err.text.indexOf("Cannot delete or update a parent row: a foreign key constraint fails",0)!=-1){
          return {success:false, result:"본 데이터는 다른 테이블에서 사용하고 있기 때문에 삭제할 수 없습니다."}
        }
        return {success:false, result:err}
      })

      res.json(qryResult)
    })
  
  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
      app.get('/getmngaccount', loginCheck, async function (req, res) {
        let qryResult = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_user " + await whereClause("tb_user",req.query.searchKeyWord))
        .then((rowResult)=>{return {success:true, result:rowResult}})
        .catch((err)=>{return {success:false, result:err}})
        res.json(qryResult)
    });

  //================================================================================ [공통 기능] 계정 부여된 권한 조회 (tb_user_auth에서 사용할 PK값 중 user_account 전달이 필요함) [Audit Trail 제외]
  app.get('/edituserauth_getuser', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_user " + await whereClause("tb_user",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 부여된 권한 조회 (tb_user_auth에서 사용할 PK값 중 user_account 전달이 필요함) [Audit Trail 제외]
    app.get('/edituserauth_getuserauth', loginCheck, async function (req, res) {
      let pk_user_account=await JSON.parse(req.query.targetPk).user_account
      let qryResult
      if(typeof(pk_user_account)!='undefined'){
      qryResult = await strFunc("SELECT tb_user_auth.user_auth as user_auth, tb_auth.auth_description as auth_description, tb_user_auth.remark, BIN_TO_UUID(tb_user_auth.uuid_binary) AS uuid_binary, tb_user_auth.insert_by as insert_by, tb_user_auth.insert_datetime as insert_datetime FROM tb_user_auth LEFT OUTER JOIN tb_auth ON tb_user_auth.user_auth = tb_auth.user_auth WHERE tb_user_auth.user_account = '"+pk_user_account+"' AND tb_user_auth.user_auth like '%"+req.query.searchKeyWord+"%'")
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})
      }
      res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 권한 부여 (tb_user_auth에서 PK로 사용할 user_account, user_auth 값 전달이 필요함) [on Audit Trail]
  app.post('/edituserauth_adduserauth', loginCheck, async function (req, res) {
    let addRows=[]
    let auditTrailRows=[]
    req.body.targetRows.map((oneTarget,i)=>{
      addRows.push([oneTarget.user_account, oneTarget.user_auth, oneTarget.insert_by])
      auditTrailRows.push([oneTarget.insert_by,oneTarget.user_account+"계정에 권한 추가",oneTarget.user_auth])
    })
    let qryResult = await batchInsertFunc('tb_user_auth',['user_account', 'user_auth', 'insert_by', 'insert_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],addRows,false)
    .then(async (rowResult)=>{
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
      return {success:true, result:rowResult}
    })
    .catch((err)=>{return {success:false, result:err}})
    
    res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 부여된 권한 삭제 (tb_user_auth에서 사용할 uuid_binary 값 전달이 필요함) [on Audit Trail]
    app.delete('/edituserauth_deleteuserauth', loginCheck, async function (req, res) {
      let uuid_binarys=[]
      let auditTrailRows=[]
      req.query.targetRows.map((oneRow,i)=>{
        let tempJsonParse=JSON.parse(oneRow)
        uuid_binarys.push("uuid_binary = UUID_TO_BIN('" + tempJsonParse.uuid_binary +"')")
        auditTrailRows.push([tempJsonParse.delete_by,tempJsonParse.user_account+"의 권한 삭제",tempJsonParse.user_auth])
      })
      let qryResult = await strFunc("DELETE FROM tb_user_auth WHERE " + uuid_binarys.join(" OR "))
      .then(async (rowResult)=>{
        await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:rowResult}
      })
      .catch((err)=>{return {success:false, result:err}})

      res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 미부여된 권한 조회 (tb_user_auth에서 사용할 PK값 중 user_account 전달이 필요함 [Audit Trail 제외]
  app.get('/edituserauth_getusernoauth', loginCheck, async function (req, res) {
    let pk_user_account=await JSON.parse(req.query.targetPk).user_account

    let qryResult
    if(typeof(pk_user_account)!='undefined'){
      qryResult = await strFunc("SELECT tb_auth.user_auth, tb_auth.auth_description, tb_auth.remark, BIN_TO_UUID(tb_auth.uuid_binary) as uuid_binary FROM (SELECT * FROM tb_user_auth WHERE user_account = '"+pk_user_account+"'"+ ") tb_user_auth_target RIGHT OUTER JOIN tb_auth ON tb_user_auth_target.user_auth = tb_auth.user_auth WHERE user_account IS null AND tb_auth.user_auth like '%"+req.query.searchKeyWord+"%'")
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})
    }
    res.json(qryResult)
});

  //================================================================================ [공통 기능] 전자서명 (현재 사용자 & 패스워드만 확인해줌) [Audit Trail 제외]
  app.get('/signpw', loginCheck, async function (req, res) {
    let user_account=req.query.user_account
    let user_pw =req.query.user_pw
    let qryResult = await strFunc("SELECT user_pw FROM tb_user where user_account = '" + req.query.user_account + "'")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    if(qryResult.result.length=1){
      if(bcrypt.compareSync(req.query.user_pw, qryResult.result[0].user_pw)){
        res.json({signStat:true, msg:"사용자인증 되었습니다."})
      }
      else{
        res.json({signStat:false, msg:"패스워드가 일치하지 않습니다."})
      }      
    }
    else{
      res.json({signStat:false, msg:"유일한 계정이 확인되지 않습니다."})
    }
});

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/duplicatedaccountCheck', loginCheck, async function(req,res){
    let qryResult = await strFunc("SELECT * FROM tb_user WHERE user_account='"+req.body.user_account+"'")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

  //================================================================================ Table의 UUID 값 때문인지  "TypeError: Do not know how to serialize a BigInt" 방지용
  BigInt.prototype.toJSON = function() {       
    return this.toString()
  }

  //================================================================================ [공통 기능] 계정 생성
  app.post('/postAddDocPattern', loginCheck, async function(req,res){
    let insertTable="tb_doc_no_pattern";
    let columNamesArr=[]
    let questions=[]
    let valueArrys=[]

    Object.keys(req.body).map(async (keyName,i)=>{
      columNamesArr.push(keyName)
      questions.push('?')
      valueArrys.push(req.body[keyName])
    })

    columNamesArr.push("insert_datetime")
    questions.push('now()')

    columNamesArr.push("uuid_binary")
    questions.push('UUID_TO_BIN(UUID())')

    let auditTrailRows=[]
    auditTrailRows.push(req.body.insert_by,"문서번호 패턴 생성 : '" + req.body.doc_no_pattern + "'",req.body.doc_no_pattern)

    let qryResult = await insertFunc(insertTable,columNamesArr,questions,valueArrys)
    .then(async (rowResult)=>{
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
      return {success:true, result:rowResult}
    })
    .catch((err)=>{return {success:false, result:err}})
    
    res.json(qryResult)
  })

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/duplicatedocpatterncheck', loginCheck, async function(req,res){
    let qryResult = await strFunc("SELECT * FROM tb_doc_no_pattern WHERE doc_no_pattern ='"+req.body.doc_no_pattern+"'")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/duplicatedocpatternnamecheck', loginCheck, async function(req,res){
    let qryResult = await strFunc("SELECT * FROM tb_doc_no_pattern WHERE pattern_name ='"+req.body.pattern_name+"'")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getmngdocnopattern', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT  pattern_name, doc_no_pattern, start_rev_no, ref_sop_no, ref_sop_rev,pattern_description, pattern_pair_code, serial_pool, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_doc_no_pattern " + await whereClause("tb_doc_no_pattern",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });

    //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
    app.get('/adddocno_getmngdocnopattern', loginCheck, async function (req, res) {
      let qryResult = await strFunc("SELECT  pattern_name, doc_no_pattern, start_rev_no, ref_sop_no, ref_sop_rev,pattern_description, pattern_pair_code, serial_pool, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_doc_no_pattern " + await whereClause("tb_doc_no_pattern",req.query.searchKeyWord))
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})
      res.json(qryResult)
    });
    //================================================================================ [공통 기능] 계정 부여된 권한 삭제 (tb_user_auth에서 사용할 uuid_binary 값 전달이 필요함) [on Audit Trail]
    app.delete('/deletedocnopattern', loginCheck, async function (req, res) {
      let uuid_binarys=[]
      let auditTrailRows=[]
      req.query.targetRows.map((oneRow,i)=>{
        let tempJsonParse=JSON.parse(oneRow)
        uuid_binarys.push("uuid_binary = UUID_TO_BIN('" + tempJsonParse.uuid_binary +"')")
        auditTrailRows.push([tempJsonParse.delete_by,"문서번호 패턴 삭제 : '"+tempJsonParse.doc_no_pattern+"'",tempJsonParse.doc_no_pattern])
      })
      let qryResult = await strFunc("DELETE FROM tb_doc_no_pattern WHERE " + uuid_binarys.join(" OR "))
      .then(async (rowResult)=>{
        await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:rowResult}
      })
      .catch((err)=>{return {success:false, result:err}})

      res.json(qryResult)
  });

    //================================================================================ [공통 기능] 계정 생성
    app.post('/postAddDocNo', loginCheck, async function(req,res){
      let insertTable="tb_doc_no_list";
      let columNamesArr=[]
      let questions=[]
      let valueArrys=[]

      // =============== 시리얼 번호 발번 시작
      let maxWholeSerial=[] // 현재까지 발번된 시리얼 번호 최대값 찾기
      for(let i =0;i<req.body.pattenrs.length;i++ ){
        // ========== 문서번호 패턴 가지고 부여된 최대 serial no 구하기
        // ===== serial자리만 없는 패턴 구하기 {2_year} 현재값 적용, {3_serial_per_year} 공란으로 변경
        let tempNoWithoutSerial = req.body.pattenrs[i].doc_no_pattern.replace("{2_year}",new Date().getFullYear().toString().substring(2,4)).replace("{3_serial_per_year}","")
        
        // 같은 패턴으로 검색해서 시리얼 자리에 들어값 값들 중 최대값 확인한기
        let patternQryResult=  await strFunc("SELECT doc_no FROM tb_doc_no_list where doc_no like '%" + tempNoWithoutSerial +"%'")
        let maxSerialInPattern =[]
        patternQryResult.map((oneValue,i)=>{
          maxSerialInPattern.push(parseInt(oneValue.doc_no.replace(tempNoWithoutSerial,'')))
        })

        // ========== serial pool 가지고 부여된 최대 serial no 구하기
        let serialQryResult = await strFunc("SELECT max(used_serial) as maxSerial FROM tb_doc_no_list where serial_pool = '" + req.body.pattenrs[i].serial_pool +"' and DATE_FORMAT(insert_datetime, '%Y') = '" + new Date().getFullYear().toString()+"'")
        let maxSerialInPool =  []
        if(!serialQryResult[0].maxSerial){
          maxSerialInPool.push(0)
        }
        else(
          maxSerialInPool.push(parseInt(serialQryResult[0].maxSerial))
        )
        maxWholeSerial.push(Math.max(Math.max.apply(null,maxSerialInPattern),Math.max.apply(null,maxSerialInPool)))
      }


      // 찾은 시리얼 최대값에 +1 더하여 새 시리얼번호 발번하기
      let newSerial = Math.max.apply(null,maxWholeSerial)+1
      // 3자리 시리얼 번호 패턴에 사용하도록 str 생성
      let serial_3digit=''
      if (newSerial>99){
        serial_3digit = ''+newSerial
      }
      else if(newSerial>9)
      {
        serial_3digit = '0'+newSerial
      }
      else {
        serial_3digit = '00'+newSerial
      }
      // =============== 시리얼 번호 발번 종료

      // =============== tb_doc_no_list 및 Audit Trail 새 Record 생성
      let docNoList=[]
      let addRows=[]
      let auditTrailRows=[]
      for(let i =0;i<req.body.pattenrs.length;i++ ){
        let tempDocNo = req.body.pattenrs[i].doc_no_pattern.replace("{2_year}",new Date().getFullYear().toString().substring(2,4)).replace("{3_serial_per_year}",serial_3digit)
        console.log(req.body.pattenrs[i].used_pattern)
        addRows.push([tempDocNo, req.body.req_purpose, req.body.req_user,req.body.req_team, req.body.pattenrs[i].doc_no_pattern, req.body.pattenrs[i].pattern_name, req.body.pattenrs[i].start_rev_no, req.body.pattenrs[i].serial_pool,newSerial,req.body.remark,req.body.insert_by])
        docNoList.push(tempDocNo)
        auditTrailRows.push([req.body.insert_by,"문서번호 생성 : '" + tempDocNo + "'",tempDocNo])
      }

      let qryResult = await batchInsertFunc(insertTable,['doc_no', 'req_purpose', 'req_user', 'req_team', 'used_pattern', 'used_pattern_name', 'start_rev_no', 'serial_pool', 'used_serial', 'remark', 'insert_by', 'insert_datetime', 'uuid_binary'], ['?','?','?','?','?','?','?','?','?','?','?','now()','UUID_TO_BIN(UUID())'],addRows,false)
      .then(async (rowResult)=>{
        await batchInsertFunc("tb_audit_trail",['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:docNoList}
      })
      .catch((err)=>{return {success:false, result:err}})

      console.log("audit result : ")
      console.log(auditTrailRows)
      console.log(qryResult)
      res.json(qryResult)
    })

  //================================================================================ 
  app.get('/getmngdocno', loginCheck, async function (req, res) {
    let whereClause = "WHERE (tb_user.user_name like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.doc_no like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.req_purpose like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.req_user like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.req_team like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.serial_pool like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.used_serial like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.remark like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.uuid_binary = UUID_TO_BIN('"+req.query.searchKeyWord+"')) OR (tb_doc_no_list.insert_datetime like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.update_datetime like '%"+req.query.searchKeyWord+"%')"
    let qryResult = await strFunc("SELECT tb_doc_no_list.doc_no, tb_doc_no_list.req_purpose, tb_doc_no_list.req_user, tb_user.user_name, tb_doc_no_list.req_team, tb_doc_no_list.used_pattern, tb_doc_no_list.used_pattern_name, tb_doc_no_list.start_rev_no, doclist.last_rev_no, doclist.count_used, tb_doc_no_list.serial_pool, tb_doc_no_list.used_serial, tb_doc_no_list.remark, BIN_TO_UUID(tb_doc_no_list.uuid_binary) AS uuid_binary, tb_doc_no_list.insert_by, tb_doc_no_list.insert_datetime, tb_doc_no_list.update_by, tb_doc_no_list.update_datetime FROM tb_doc_no_list LEFT OUTER JOIN tb_user ON tb_doc_no_list.req_user = tb_user.user_account LEFT OUTER JOIN (SELECT doc_no, MAX(rev_no) AS last_rev_no, COUNT(doc_no) as count_used FROM tb_doc_list GROUP BY doc_no) AS doclist ON doclist.doc_no = tb_doc_no_list.doc_no " + whereClause +  " ORDER BY tb_doc_no_list.insert_datetime DESC")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });

  //================================================================================ 
  app.delete('/deletedocno', loginCheck, async function (req, res) {
    let uuid_binarys=[]
    let auditTrailRows=[]
    req.query.targetRows.map((oneRow,i)=>{
      let tempJsonParse=JSON.parse(oneRow)
      uuid_binarys.push("uuid_binary = UUID_TO_BIN('" + tempJsonParse.uuid_binary +"')")
      auditTrailRows.push([tempJsonParse.delete_by,"문서번호 삭제 : '"+tempJsonParse.doc_no+"'",tempJsonParse.doc_no])
    })
    let qryResult = await strFunc("DELETE FROM tb_doc_no_list WHERE " + uuid_binarys.join(" OR "))
    .then(async (rowResult)=>{
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
      return {success:true, result:rowResult}
    })
    .catch((err)=>{return {success:false, result:err}})

    res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/adddoc_getmngdocno', loginCheck, async function (req, res) {
    console.log(req.query.searchKeyWord)
    let whereClause = "WHERE (tb_user.user_name like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.doc_no like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.req_purpose like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.req_user like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.req_team like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.serial_pool like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.used_serial like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.remark like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.uuid_binary = UUID_TO_BIN('"+req.query.searchKeyWord+"')) OR (tb_doc_no_list.insert_datetime like '%"+req.query.searchKeyWord+"%') OR (tb_doc_no_list.update_datetime like '%"+req.query.searchKeyWord+"%')"
    let qryResult = await strFunc("SELECT tb_doc_no_list.doc_no, tb_doc_no_list.req_purpose, tb_doc_no_list.req_user, tb_user.user_name, tb_doc_no_list.req_team, tb_doc_no_list.used_pattern, tb_doc_no_list.used_pattern_name, tb_doc_no_list.start_rev_no, doclist.last_rev_no, doclist.count_used, tb_doc_no_list.serial_pool, tb_doc_no_list.used_serial, tb_doc_no_list.remark, BIN_TO_UUID(tb_doc_no_list.uuid_binary) AS uuid_binary, tb_doc_no_list.insert_by, tb_doc_no_list.insert_datetime, tb_doc_no_list.update_by, tb_doc_no_list.update_datetime FROM tb_doc_no_list LEFT OUTER JOIN tb_user ON tb_doc_no_list.req_user = tb_user.user_account LEFT OUTER JOIN (SELECT doc_no, MAX(rev_no) AS last_rev_no, COUNT(doc_no) as count_used FROM tb_doc_list GROUP BY doc_no) AS doclist ON doclist.doc_no = tb_doc_no_list.doc_no " + whereClause +  " ORDER BY tb_doc_no_list.insert_datetime DESC")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 생성
  app.post('/postAddDoc', loginCheck, async function(req,res){
    let insertTable="tb_doc_list";
    let columNamesArr=[]
    let questions=[]
    let valueArrys=[]

    Object.keys(req.body).map(async (keyName,i)=>{
      columNamesArr.push(keyName)
      questions.push('?')
      valueArrys.push(req.body[keyName])
    })

    columNamesArr.push("insert_datetime")
    questions.push('now()')

    columNamesArr.push("uuid_binary")
    questions.push('UUID_TO_BIN(UUID())')

    let auditTrailRows=[]
    auditTrailRows.push(req.body.insert_by,"문서 정보 추가 : '" + req.body.doc_no + "("+ req.body.rev_no +")'",{doc_no:req.body.doc_no, rev_no:req.body.rev_no})

    console.log("컬럼 길이:"+columNamesArr.length + "/ " + columNamesArr)
    console.log("물음펴 길이:"+questions.length + "/ " + questions)
    console.log("값 길이:"+valueArrys.length + "/ " + valueArrys)

    let qryResult = await insertFunc(insertTable,columNamesArr,questions,valueArrys)
    .then(async (rowResult)=>{
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
      return {success:true, result:rowResult}
    })
    .catch((err)=>{return {success:false, result:err}})
    
    res.json(qryResult)
  })

   //================================================================================ [문서 기능] 문서 정보 수정
   app.put('/puteditdoc',loginCheck,async function(req,res){
    let auditTrailDataBefore= await strFunc("SELECT doc_no, rev_no, doc_title, written_by, written_by_team, approval_date, invalid_date, qualAtt, valAtt, eqAtt, prodAtt, eqmsAtt, isprotocol, relateddoc, remark FROM tb_doc_list WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
    let auditTrailDataAfter=[]
    let auditTrailRows=[]

    let setArrys=[]

    Object.keys(req.body).map(async (keyName,i)=>{
      if(keyName=="uuid_binary"){ 
        // uuid는 업데이트할 Row 검색 조건이기 때문에 변경 안 함
      }
      else if(keyName=="doc_no"){
        // doc_no는 PK이기 때문에 변경 안 함
      }
      else if(keyName=="rev_no"){
        // rev_no는 PK이기 때문에 변경 안 함
      }
      else{
        if(typeof(req.body[keyName])=="string") setArrys.push(keyName+"='"+req.body[keyName]+"'")
        else if(typeof(req.body[keyName])=="number") setArrys.push(keyName+"="+req.body[keyName]+"")
        else if(!req.body[keyName]) setArrys.push(keyName+"=NULL")
      }
    })

    setArrys.push("update_datetime=now()")

    console.log(setArrys)
    let qryResult = await strFunc("UPDATE tb_doc_list SET "+ setArrys.join(",") + " WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
    .then(async (rowResult)=>{
      auditTrailDataAfter = await strFunc("SELECT doc_no, rev_no, doc_title, written_by, written_by_team, approval_date, invalid_date, qualAtt, valAtt, eqAtt, prodAtt, eqmsAtt, isprotocol, relateddoc, remark FROM tb_doc_list WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
      
      auditTrailRows.push(req.body.update_by,"'" + req.body.doc_no +"("+req.body.rev_no+")" + "' 의 정보수정", JSON.stringify({Before:auditTrailDataBefore,After:auditTrailDataAfter}))
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

      return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

    //================================================================================ 
    app.get('/getmngdoc', loginCheck, async function (req, res) {
      let whereClause ="WHERE "
      + "(tb_doc_list.doc_no like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.rev_no like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.doc_title like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.written_by like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.written_by_team like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.approval_date like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.invalid_date like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.qualAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.valAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.eqAtt like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.prodAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.eqmsAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.isprotocol like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.relateddoc like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.remark like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_user.user_name like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.uuid_binary = UUID_TO_BIN('"+req.query.searchKeyWord+"')) OR (tb_doc_list.insert_datetime like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.update_datetime like '%"+req.query.searchKeyWord+"%')"

      let qryResult = await strFunc("SELECT "
      + "tb_doc_list.doc_no, tb_doc_list.rev_no, tb_doc_list.doc_title, tb_doc_list.written_by, tb_user.user_name, tb_doc_list.written_by_team, tb_doc_list.approval_date, tb_doc_list.invalid_date, tb_doc_list.remark, "
      + "tb_doc_list.qualAtt, tb_doc_list.valAtt, tb_doc_list.eqAtt, tb_doc_list.prodAtt, tb_doc_list.eqmsAtt, tb_doc_list.isprotocol, tb_doc_list.relateddoc, "
      + "BIN_TO_UUID(tb_doc_list.uuid_binary) AS uuid_binary,  tb_doc_list.insert_by,  tb_doc_list.insert_datetime,  tb_doc_list.update_by,  tb_doc_list.update_datetime "
      + "FROM tb_doc_list LEFT OUTER JOIN tb_user ON tb_doc_list.written_by = tb_user.user_account " + whereClause+" ORDER BY tb_doc_list.insert_datetime DESC" )
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})
      res.json(qryResult)
    });

    //================================================================================ 
    app.get('/adddoc_getmngdoc', loginCheck, async function (req, res) {
      let whereClause ="WHERE "
      + "(tb_doc_list.doc_no like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.rev_no like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.doc_title like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.written_by like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.written_by_team like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.approval_date like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.invalid_date like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.qualAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.valAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.eqAtt like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.prodAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.eqmsAtt like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.isprotocol like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.relateddoc like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.remark like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_user.user_name like '%"+req.query.searchKeyWord+"%')"
      + " OR (tb_doc_list.uuid_binary = UUID_TO_BIN('"+req.query.searchKeyWord+"')) OR (tb_doc_list.insert_datetime like '%"+req.query.searchKeyWord+"%') OR (tb_doc_list.update_datetime like '%"+req.query.searchKeyWord+"%')"

      let qryResult = await strFunc("SELECT "
      + "tb_doc_list.doc_no, tb_doc_list.rev_no, tb_doc_list.doc_title, tb_doc_list.written_by, tb_user.user_name, tb_doc_list.written_by_team, tb_doc_list.approval_date, tb_doc_list.invalid_date, tb_doc_list.remark, "
      + "tb_doc_list.qualAtt, tb_doc_list.valAtt, tb_doc_list.eqAtt, tb_doc_list.prodAtt, tb_doc_list.eqmsAtt, tb_doc_list.isprotocol, tb_doc_list.relateddoc, "
      + "BIN_TO_UUID(tb_doc_list.uuid_binary) AS uuid_binary,  tb_doc_list.insert_by,  tb_doc_list.insert_datetime,  tb_doc_list.update_by,  tb_doc_list.update_datetime "
      + "FROM tb_doc_list LEFT OUTER JOIN tb_user ON tb_doc_list.written_by = tb_user.user_account " + whereClause+" ORDER BY tb_doc_list.insert_datetime DESC" )
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})
      res.json(qryResult)
    });

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/postextdatatmms', loginCheck, async function(req,res){
    let columNamesArr=['data_order', 'eq_team', 'eq_part', 'eq_location', 
    'drug_form', 'room_no', 'eq_code_alt', 'eq_code', 'eq_name', 'eq_grade', 'eq_inst_date', 'eq_capa', 'eq_model', 'eq_serial', 
    'eq_manf', 'eq_vendor', 'eq_is_legal', 'manuf_country', 'used_util', 'eq_cat', 'rev_status', 'is_latest', 'data_rev', 'eq_status',
    'insert_by', 'insert_datetime','update_by', 'update_datetime', 'uuid_binary']
    let questions=['?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?',"'"+req.body.handle_by+"'",'now()','NULL','NULL','UUID_TO_BIN(UUID())']
    let valueArrys=[]
    let dupStrArry=['data_order=VALUES(data_order)','eq_team=VALUES(eq_team)','eq_part=VALUES(eq_part)','eq_location=VALUES(eq_location)','drug_form=VALUES(drug_form)','room_no=VALUES(room_no)',
    'eq_code_alt=VALUES(eq_code_alt)','eq_name=VALUES(eq_name)','eq_grade=VALUES(eq_grade)','eq_inst_date=VALUES(eq_inst_date)','eq_capa=VALUES(eq_capa)','eq_model=VALUES(eq_model)','eq_serial=VALUES(eq_serial)',
    'eq_manf=VALUES(eq_manf)','eq_vendor=VALUES(eq_vendor)','eq_is_legal=VALUES(eq_is_legal)','manuf_country=VALUES(manuf_country)','used_util=VALUES(used_util)', 
    'eq_cat=VALUES(eq_cat)','rev_status=VALUES(rev_status)','is_latest=VALUES(is_latest)','data_rev=VALUES(data_rev)','eq_status=VALUES(eq_status)',"update_by='"+req.body.handle_by+"'",'update_datetime=now()']

    req.body.extdatas.map((oneRow,i)=>{
      let oneValueArry=[]
      Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
        oneValueArry.push(req.body.extdatas[i][keyName])
      })
      valueArrys.push(oneValueArry)
    })

    let qryResult = await batchInsertOnDupliFunc("tb_extdata_tmms_whole_asset",columNamesArr,questions,valueArrys,dupStrArry)
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getextdatatmmswholeasset', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT data_order, eq_team, eq_part, eq_location, drug_form, room_no, eq_code_alt, eq_code, eq_name, eq_grade, eq_inst_date, eq_capa, eq_model, eq_serial, eq_manf, eq_vendor, eq_is_legal, manuf_country, used_util, eq_cat, rev_status, is_latest, data_rev, eq_status, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by,insert_datetime, update_by, update_datetime FROM tb_extdata_tmms_whole_asset " + await whereClause("tb_extdata_tmms_whole_asset",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
});
  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/adddoc_getextdatatmmswholeasset', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT eq_code_alt, eq_code, eq_name, eq_team, eq_part, eq_location, drug_form, room_no, eq_grade, eq_inst_date, eq_capa, eq_model, eq_serial, eq_manf, eq_vendor, eq_is_legal, manuf_country, used_util, eq_cat, rev_status, is_latest, data_rev, eq_status, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by,insert_datetime, update_by, update_datetime FROM tb_extdata_tmms_whole_asset " + await whereClause("tb_extdata_tmms_whole_asset",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
});

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/postextdatasapzmmr1010', loginCheck, async function(req,res){
    let columNamesArr=['mat_cat', 'plant_code', 'mat_code', 'mat_name', 'mat_unit', 'mat_unit_name', 'mat_code_alt1', 'mat_code_alt2', 'mat_code_alt3',
    'mat_code_alt4', 'mat_code_alt5', 'mat_code_alt6', 'mat_unit_alt1', 'mat_unit_alt1_name', 'mat_unit_alt1_value', 'mat_group', 'mat_ext_group',
    'status_plants', 'status_mats_plants', 'max_store_level', 'prod_cat', 'prod_scrap', 'mrp_group', 'buy_group', 'mrp_cat', 'reorder_point', 'mrp_manager', 
    'lot_size', 'lot_min_size', 'lot_max_size', 'lot_fix', 'assemble_group', 'provide_specical', 'provide_cat', 'production_store_location', 
    'use_quater', 'ep_store_location', 'internal_production', 'intend_prodvide', 'leadtime_import', 'safe_time_indicator', 'safe_time', 'production_director', 
    'delivery_tolerance_below', 'delivery_tolerance_above', 'temp_condition', 'mat_group_pack_mat', 'store_condition', 'remained_effect', 'total_shelf_life', 
    'check_setting', 'provide_specical_cat', 'vendor_list', 'auto_po', 'lab_design_room', 'prod_layer_skeleton', 'layer1_name', 'layer2_name', 'layer3_name', 
    'layer4_name', 'round_value', 'plant_delete', 'whole_delete', 'record_datetime', 'lastest_datetime', 'record_cat', 'std_text', 'std_code', 'std_code_name', 
    'rep_code', 'std_code_alt1', 'insurance_code', 'approval_cat', 'approval_cat_name', 'approval_name', 'evaluation_class', 'pack_unit_authority', 'pack_unit_prod_code', 
    'mat_account_group', 'safe_stock', 'min_safe_stock', 'provided_plant', 'uuid_binary', 'insert_by', 'insert_datetime', 'update_by', 'update_datetime']
    let questions=['?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?',  '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', 
    'UUID_TO_BIN(UUID())', "'"+req.body.handle_by+"'", 'now()', 'NULL', 'NULL']
    let valueArrys=[]
    let dupStrArry=[
      'mat_cat= VALUES(mat_cat)', 'plant_code= VALUES(plant_code)', 'mat_code= VALUES(mat_code)', 'mat_name= VALUES(mat_name)', 'mat_unit= VALUES(mat_unit)',
      'mat_unit_name= VALUES(mat_unit_name)', 'mat_code_alt1= VALUES(mat_code_alt1)', 'mat_code_alt2= VALUES(mat_code_alt2)', 'mat_code_alt3= VALUES(mat_code_alt3)',
      'mat_code_alt4= VALUES(mat_code_alt4)', 'mat_code_alt5= VALUES(mat_code_alt5)', 'mat_code_alt6= VALUES(mat_code_alt6)', 'mat_unit_alt1= VALUES(mat_unit_alt1)',
      'mat_unit_alt1_name= VALUES(mat_unit_alt1_name)', 'mat_unit_alt1_value= VALUES(mat_unit_alt1_value)', 'mat_group= VALUES(mat_group)', 'mat_ext_group= VALUES(mat_ext_group)',
      'status_plants= VALUES(status_plants)', 'status_mats_plants= VALUES(status_mats_plants)', 'max_store_level= VALUES(max_store_level)', 'prod_cat= VALUES(prod_cat)',
      'prod_scrap= VALUES(prod_scrap)', 'mrp_group= VALUES(mrp_group)', 'buy_group= VALUES(buy_group)', 'mrp_cat= VALUES(mrp_cat)', 'reorder_point= VALUES(reorder_point)',
      'mrp_manager= VALUES(mrp_manager)', 'lot_size= VALUES(lot_size)', 'lot_min_size= VALUES(lot_min_size)', 'lot_max_size= VALUES(lot_max_size)', 'lot_fix= VALUES(lot_fix)',
      'assemble_group= VALUES(assemble_group)', 'provide_specical= VALUES(provide_specical)', 'provide_cat= VALUES(provide_cat)', 'production_store_location= VALUES(production_store_location)',
      'use_quater= VALUES(use_quater)', 'ep_store_location= VALUES(ep_store_location)', 'internal_production= VALUES(internal_production)', 'intend_prodvide= VALUES(intend_prodvide)',
      'leadtime_import= VALUES(leadtime_import)', 'safe_time_indicator= VALUES(safe_time_indicator)', 'safe_time= VALUES(safe_time)', 'production_director= VALUES(production_director)',
      'delivery_tolerance_below= VALUES(delivery_tolerance_below)', 'delivery_tolerance_above= VALUES(delivery_tolerance_above)', 'temp_condition= VALUES(temp_condition)',
      'mat_group_pack_mat= VALUES(mat_group_pack_mat)', 'store_condition= VALUES(store_condition)', 'remained_effect= VALUES(remained_effect)', 'total_shelf_life= VALUES(total_shelf_life)',
      'check_setting= VALUES(check_setting)', 'provide_specical_cat= VALUES(provide_specical_cat)', 'vendor_list= VALUES(vendor_list)', 'auto_po= VALUES(auto_po)', 'lab_design_room= VALUES(lab_design_room)',
      'prod_layer_skeleton= VALUES(prod_layer_skeleton)', 'layer1_name= VALUES(layer1_name)', 'layer2_name= VALUES(layer2_name)', 'layer3_name= VALUES(layer3_name)', 'layer4_name= VALUES(layer4_name)',
      'round_value= VALUES(round_value)', 'plant_delete= VALUES(plant_delete)', 'whole_delete= VALUES(whole_delete)', 'record_datetime= VALUES(record_datetime)', 'lastest_datetime= VALUES(lastest_datetime)',
      'record_cat= VALUES(record_cat)', 'std_text= VALUES(std_text)', 'std_code= VALUES(std_code)', 'std_code_name= VALUES(std_code_name)', 'rep_code= VALUES(rep_code)', 'std_code_alt1= VALUES(std_code_alt1)',
      'insurance_code= VALUES(insurance_code)', 'approval_cat= VALUES(approval_cat)', 'approval_cat_name= VALUES(approval_cat_name)', 'approval_name= VALUES(approval_name)', 'evaluation_class= VALUES(evaluation_class)',
      'pack_unit_authority= VALUES(pack_unit_authority)', 'pack_unit_prod_code= VALUES(pack_unit_prod_code)', 'mat_account_group= VALUES(mat_account_group)', 'safe_stock= VALUES(safe_stock)', 'min_safe_stock= VALUES(min_safe_stock)',
      'provided_plant= VALUES(provided_plant)',"update_by='"+req.body.handle_by+"'",'update_datetime=now()'
    ]

    req.body.extdatas.map((oneRow,i)=>{
      let oneValueArry=[]
      Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
        oneValueArry.push(req.body.extdatas[i][keyName])
      })
      valueArrys.push(oneValueArry)
    })

    let qryResult = await batchInsertOnDupliFunc("tb_extdata_sapzmmrten",columNamesArr,questions,valueArrys,dupStrArry)
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/adddoc_getextdatasapzmmr1010', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT mat_cat, plant_code, mat_code, mat_name, mat_unit, mat_unit_name, mat_code_alt1, mat_code_alt2, mat_code_alt3, "
    + "mat_code_alt4, mat_code_alt5, mat_code_alt6, mat_unit_alt1, mat_unit_alt1_name, mat_unit_alt1_value, mat_group, mat_ext_group, status_plants, "
    + "status_mats_plants, max_store_level, prod_cat, prod_scrap, mrp_group, buy_group, mrp_cat, reorder_point, mrp_manager, lot_size, lot_min_size, "
    + "lot_max_size, lot_fix, assemble_group, provide_specical, provide_cat, production_store_location, use_quater, ep_store_location, internal_production, "
    + "intend_prodvide, leadtime_import, safe_time_indicator, safe_time, production_director, delivery_tolerance_below, delivery_tolerance_above, temp_condition, "
    + "mat_group_pack_mat, store_condition, remained_effect, total_shelf_life, check_setting, provide_specical_cat, vendor_list, auto_po, lab_design_room, "
    + "prod_layer_skeleton, layer1_name, layer2_name, layer3_name, layer4_name, round_value, plant_delete, whole_delete, record_datetime, lastest_datetime, "
    + "record_cat, std_text, std_code, std_code_name, rep_code, std_code_alt1, insurance_code, approval_cat, approval_cat_name, approval_name, evaluation_class, "
    + "pack_unit_authority, pack_unit_prod_code, mat_account_group, safe_stock, min_safe_stock, provided_plant, "
    + "BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_extdata_sapzmmrten " + await whereClause("tb_extdata_sapzmmrten",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/postextdataeqmsatemplate', loginCheck, async function(req,res){
    // req.body.extdatas.map((oneRow,i)=>{
    //   console.log(oneRow)
    // })
    let columNamesArr=['pr_no', 'create_datetime', 'project', 'pr_title', 'written_by', 'due_date', 'pr_state', 'date_closed', 
    'uuid_binary', 'insert_by', 'insert_datetime', 'update_by', 'update_datetime', ]
    let questions=['?', '?', '?', '?', '?', '?', '?', '?', 'UUID_TO_BIN(UUID())', "'"+req.body.handle_by+"'", 'now()', 'NULL', 'NULL']
    let valueArrys=[]
    let dupStrArry=['pr_no= VALUES(pr_no)', 'create_datetime= VALUES(create_datetime)', 'project= VALUES(project)', 'pr_title= VALUES(pr_title)',
    'written_by= VALUES(written_by)', 'due_date= VALUES(due_date)', 'pr_state= VALUES(pr_state)', 'date_closed= VALUES(date_closed)',
    "update_by='"+req.body.handle_by+"'", 'update_datetime=now()']

    req.body.extdatas.map((oneRow,i)=>{
      let oneValueArry=[]
      Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
        oneValueArry.push(req.body.extdatas[i][keyName])
      })
      if (oneValueArry.length==8) valueArrys.push(oneValueArry)
      else console.log(oneValueArry)
    })

    let qryResult = await batchInsertOnDupliFunc("tb_extdata_eqms_a_template",columNamesArr,questions,valueArrys,dupStrArry)
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })
  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/adddoc_getextdataeqmsatemplate', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT pr_no, project, pr_title, create_datetime, written_by, due_date, pr_state, date_closed, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_extdata_eqms_a_template " + await whereClause("tb_extdata_eqms_a_template",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });
  //================================================================================ [공통 기능] 모든 route를 react SPA로 연결 (이 코드는 맨 아래 있어야함)
    app.get('/', function (req, res) {
      res.sendFile(path.join(__dirname, process.env.react_build_path+'index.html'));
    });
  
    app.get('*', function (req, res) {
      res.sendFile(path.join(__dirname, process.env.react_build_path+'index.html'));
    });