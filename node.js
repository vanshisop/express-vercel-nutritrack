// server.js
////
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { user, password } = require('pg/lib/defaults');
const app = express();
const port = process.env.PORT || 3001;
const { Pool } = require('pg');
const bcrypt = require('bcrypt')
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const cookieParser = require('cookie-parser');
const axios = require("axios");
const { log } = require('console');
const openaiApiKey = process.env.OPEN_API_KEY
async function searchFoods({ search_expression, page_number = 0, max_results = 20, format = 'json', generic_description, region, language }) {

    const params = {
      method: 'foods.search',
      search_expression,
      page_number,
      max_results,
      format,
      generic_description,
      region,
      language,
    };
  
    try {
      const response = await axios.get("https://platform.fatsecret.com/rest/foods/search/v1", {
        headers: {
          Authorization: `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwOEFEREZGRjZBNDkxOUFBNDE4QkREQTYwMDcwQzE5NzNDRjMzMUUiLCJ0eXAiOiJhdCtqd3QiLCJ4NXQiOiJFSXJkX19ha2tacWtHTDNhWUFjTUdYUFBNeDQifQ.eyJuYmYiOjE3MzAyNDA4NDYsImV4cCI6MTczMDMyNzI0NiwiaXNzIjoiaHR0cHM6Ly9vYXV0aC5mYXRzZWNyZXQuY29tIiwiYXVkIjoiYmFzaWMiLCJjbGllbnRfaWQiOiI3NDRiNzNlNTZjMTE0ZDdlODgwZmFlZDQ2M2VjYmI5OCIsInNjb3BlIjpbImJhc2ljIl19.NlO-fCidX-_pA5iiG28jwfn-fCWscIpkoBSezbtPWsjrxiLql01Kc8yk6rnxZCv7qlJnbEXsvM1h4iRI2Rey6PdS6EC580xNjweaJ3zhBZ0GawVavLSMtC4kEdZzCxuZggBFUCfoMfyP3soUK7Ydalx6xYbiuukiFxB4rRrXAKwcXh6NbVRadpOlS94KrjAAsSoXQJv0qr3F0j7ynnhVGjzS0-pOlaIEukZOHJSCkQtp1jw5euJq8eFqHYxeISE87sOjZ-_m7BWjZZiky1ao0K0tpy7RsXxEyNvZB0be1Y2iJsJhvs2z-I1RmQZT4q9-E4-_1Qb92LxIKgMMXd_48oOhbcnWqHSu55Uj2UnvOalCWop2C-6jmZHDGzphAu-vXfIEqgxD5v1rt_jubQLBbbv37oBAbUDAfii8e0PNXDPW1Kw5hceqdpIRBPubYq_zV7ete9AdNlqM_f90AdSwQs0g9xYdKc5imkd7HpsmQ6B4KbovYMtIm9CROd55valkQU2gW8bi2DB3Axz5tZlIOdMYUPMuws_K8t_sT6-TS-7fvCH69HePcRI1JtrY5FCWxvmOhN6QbdUavkAIKSksQPYSbYXkOm2H-efpJhoTXZIt4TEPQIB8dyy4yDZYaSo2xe1O4NQ3mmnofWf4124ji4BOhcyo3pNdBV266Rszp1Y`,
        },
        params,
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching foods:', error.response ? error.response.data : error.message);
      throw error;
    }
  }

const pool = new Pool({
  connectionString: 'postgresql://postgres.kgdxqxgmlfpwzelyamxv:_CPGJypV9RU$Nq-@aws-0-us-west-1.pooler.supabase.com:6543/postgres',
});     
function generateCaloriesForLast30Days(data) {
    // Create a mapping of the original calorie data for quick lookup
    const caloriesMap = {};
    data.forEach(item => {
      const dateKey = new Date(item.date).toISOString().split('T')[0]; // Format date as YYYY-MM-DD
      caloriesMap[dateKey] = item.total_calories; // Use the formatted date as key
    });
  
    // Get today's date
    const today = new Date();
    const result = [];
  
    // Iterate through the last 30 days in ascending order
    for (let i = 0; i < 30; i++) {
      const currentDate = new Date(today);
      currentDate.setDate(today.getDate() - (29 - i)); // Go back 29-i days
      const dateKey = currentDate.toISOString().split('T')[0]; // Format date as YYYY-MM-DD
  
      // Assign calories or null based on existence in original data
      result.push({
        date: dateKey,
        calories: caloriesMap[dateKey] || null, // Use the calories or null if not present
      });
    }
  
    return result;
  }
  function generateWeightsForLast30Days(data) {
    // Create a mapping of the original weight data for quick lookup
    const weightMap = {};
    data.forEach(item => {
        const dateKey = new Date(item.date).toISOString().split('T')[0]; // Format date as YYYY-MM-DD
        weightMap[dateKey] = item.weight; // Use the formatted date as key
    });

    // Get today's date
    const today = new Date();
    const result = [];

    // Iterate through the last 30 days in ascending order
    for (let i = 0; i < 30; i++) {
        const currentDate = new Date(today);
        currentDate.setDate(today.getDate() - (29 - i)); // Go back 29-i days
        const dateKey = currentDate.toISOString().split('T')[0]; // Format date as YYYY-MM-DD

        // Assign weight or null based on existence in original data
        result.push({
            date: dateKey,
            weight: weightMap[dateKey] || null, // Use the weight or null if not present
        });
    }

    return result;
}

const allowedOrigins = [
  'https://nutritrack-three.vercel.app',
  'http://localhost:3000',
  'http://10.182.75.200:3000'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      // Allow requests with no origin (like mobile apps or curl)
      callback(null, origin); // Reflect the origin in response
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies/auth headers
};

app.use(cors(corsOptions));

app.use(cookieParser());
app.use(bodyParser.json());


app.post('/add-registration',async (req,res)=>{
    let { fullName, registerEmail, password, sex, birthday,curWeight,targetWeight,calories, carbs, fats,protein,lifestyle,goals,height,isKg } = req.body;

const validatePassword = (value) => {
        const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/
        return regex.test(value)
      }
// Validate input data before using it in the query
const saltRounds = 10; // Ensure saltRounds is defined

const q = "SELECT full_name FROM users WHERE email = $1"
const checkEmail = await pool.query(q, [registerEmail]);
if (checkEmail.rows.length>0 || !validatePassword(password)){
    
    res.json({
        isRegistered: checkEmail.rows.length == 0 ,
        password: validatePassword(password)
        
    })
    return
}

if (isKg) {
    const kgToPounds = 2.20462;
    curWeight = (curWeight * kgToPounds).toFixed(1); // Convert and round to one decimal place
    targetWeight = (targetWeight * kgToPounds).toFixed(1); // Convert and round to one decimal place
   
}

bcrypt.hash(password, saltRounds, async (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }

    // Now proceed with the database query using the hashed password
    const values = [fullName, registerEmail, hash, sex, birthday,curWeight,targetWeight,curWeight,calories,protein,fats,carbs,lifestyle,goals,height];
    const query = "INSERT INTO users (full_name, email, password, sex, birthday,current_weight,target_weight,initial_weight,goal_cals,goal_protein,goal_fats,goal_carbs,lifestyle,goals,height) VALUES ($1, $2, $3, $4, $5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ";

    try {
        console.log("AKS");
        const userResponse = await pool.query(query, values);

       
        res.json({
                isRegistered: true,
                password: true
        });
        
    } catch (error) {
        
        console.error('Error inserting user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

    const sanitizedEmail = registerEmail.replace(/[^a-zA-Z0-9]/g, '_');
    const tableName = `user_${sanitizedEmail}_preferences`;

    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id SERIAL PRIMARY KEY,
        preference_key VARCHAR(255) NOT NULL,
        preference_value VARCHAR(255) NOT NULL
      )
    `
    
    
})
app.post('/suggest-breakdown',async (req,res)=>{
    const calculateAge = (birthday) => {
        // Convert birthday string to a Date object
        const birthDate = new Date(birthday);
      
        // Validate the date
        if (isNaN(birthDate.getTime())) {
          throw new Error("Invalid date format. Please provide a valid date string (e.g., 'YYYY-MM-DD').");
        }
      
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
      
        const monthDiff = today.getMonth() - birthDate.getMonth();
        const dayDiff = today.getDate() - birthDate.getDate();
      
        if (monthDiff < 0 || (monthDiff === 0 && dayDiff < 0)) {
          age--; // Adjust age if birthday hasn't occurred yet this year
        }
      
        return age;
      };
      
    let { sex,birthday,curWeight,targetWeight,lifestyle,goal,height,isKg } = req.body;
    console.log(goal);
    console.log(lifestyle);
    if (!isKg){
        curWeight = parseFloat((curWeight * 0.453592).toFixed(1));
        targetWeight = parseFloat((targetWeight * 0.453592).toFixed(1));
    }
 
    const age = calculateAge(birthday)
    const lifeStyleMap = {
        "Sedentary": 1.2,
        "Lightly Active": 1.375,
        "Moderately Active": 1.55,
        "Very Active": 1.725,
        "Extra Active": 1.9
    }
    const targetMap= {
        "Maintenance / General Fitness": { proteins : 0.20, fats: 0.3, carbs: 0.5},
        "Muscle Building": { proteins : 0.25, fats: 0.3, carbs: 0.45},
        "Endurance": { proteins : 0.20, fats: 0.25, carbs: 0.55},
        "Athletic Performance": { proteins : 0.20, fats: 0.20, carbs: 0.60}

    }
    let calorie = 0 ;
    if(sex!="female"){
        calorie = (10*curWeight+6.25*height-5*age+5)*lifeStyleMap[lifestyle]
    }
    else{
        calorie = (10*curWeight+6.25*height-5*age-161)*lifeStyleMap[lifestyle]
    }
    console.log(calorie);
    if(Math.abs(targetWeight - curWeight) <= 1){
        
    }
    else if (targetWeight < curWeight){
        console.log("ass");
        if (curWeight - targetWeight > 8)
            calorie = 0.80 * calorie 
        else{
            calorie *= 0.90 
      
        }
    }
    else{
        if (targetWeight - curWeight > 8)
            calorie = 1.21 * calorie 
        else
            calorie *= 1.10 
    }
    console.log(targetMap[goal]);

    const responseObject = {
        calories: calorie,
        protein: ((calorie * targetMap[goal]["proteins"]) / 4) | 0, // Integer division
        carbs: ((calorie * targetMap[goal]["carbs"]) / 4) | 0,    // Integer division
        fats: ((calorie * targetMap[goal]["fats"]) / 9) | 0        // Integer division
    };
      
    // Print the object to the console before sending
    console.log(responseObject);
    res.json({calories: calorie | 0,protein: (calorie*targetMap[goal]["proteins"]/4)|0,carbs:(calorie*targetMap[goal]["carbs"]/4)|0,fats: (calorie*targetMap[goal]["fats"]/9)|0  })

})

app.post('/login', async (req, res) => {
    const { loginEmail, loginPassword } = req.body;

    try {
        const query = "SELECT * from users WHERE email=$1";
        const userResponse = await pool.query(query, [loginEmail]);

        if (userResponse.rows.length > 0) {
            const user = userResponse.rows[0]; // Extract the user data from the response

            // Compare the provided password with the stored hashed password
            bcrypt.compare(loginPassword, user.password, (err, result) => {
                if (err) {
                    console.error('Error comparing password:', err);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (result) {
                    // Create the JWT token with the user's id, name, and email
                    console.log(user.name)
                    const token = jwt.sign(
                        { id: user.user_id, name: user.full_name, email: user.email, i_weight: user.initial_weight, t_weight: user.target_weight, c_weight: user.current_weight },
                        "abcdefghijklmnnop",
                        { expiresIn: '1h' }
                    );

                    // Set the JWT token as a cookie
                    res.cookie('authToken', token, {
                        httpOnly: true,
                        maxAge: 3600000, // 1 hour in milliseconds
                        secure: true, // Set to true if using HTTPS
                        sameSite: 'None', // Set to 'None' if using cross-site cookies
                        path: '/' // Cookie is accessible from all paths,
                    });

                    res.json({ login: "allow" });
                    console.log("User successfully logged in");
                } else {
                    res.json({ login: "Incorrect password" });
                    console.log("Incorrect password");
                }
            });
        } else {
            res.json({ login: "User does not exist" });
            console.log("User not found");
        }
    } catch (error) {
        console.error('Database query error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.post('/forgotPassword',async (req,res)=>{
    const token = crypto.randomBytes(32).toString('hex'); // Generate the reset token
    const query = "SELECT * from users WHERE email=$1";
    const userResponse = await pool.query(query, [req.body.email]);

    if(userResponse.rows.length > 0){
        // Store the token and expiration in the database
        const expirationTime = Date.now() + 3600000; // 1 hour expiration
        const expirationTimeInSeconds = Math.floor((Date.now() + 3600000) / 1000);
        const updateQuery = `
            UPDATE users SET token=$1, expiration_time=to_timestamp($2)  
            WHERE email=$3 RETURNING *`;
        await pool.query(updateQuery, [token, expirationTimeInSeconds, req.body.email]);

        // Set up Nodemailer transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "saxenavansh0804@gmail.com" ,
                pass: "wilu silg cvml urmv"
            }
        });

        // Prepare email with a reset link containing the token
        const resetLink = `http://localhost:3000/resetPassword?token=${token}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: 'Password Reset',
            text: `You requested a password reset. Click here to reset your password: ${resetLink}`
        };

        // Send the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.error("Error sending mail: ", error);
            }
            console.log("Email sent: ", info.response);
        });

        console.log("Success: Password reset email sent");
        res.json({ success: true, message: "Password reset email sent." });
    }
    else {
    res.status(404).json({ success: false, message: "User not found." });
    }
})

app.post('/resetPasswordPage',async (req,res)=>{
    console.log("hi")
    const query = "SELECT expiration_time from users WHERE token=$1";
    const userResponse = await pool.query(query, [req.body.token]);
    
    if(userResponse.rows.length > 0){
        // Store the token and expiration in the database
        const { expiration_time } = userResponse.rows[0]; // Get the expiration time
           
            // Check if the token is expired
            const currentTime = Date.now(); // Get current time in milliseconds
            const isExpired = new Date(expiration_time).getTime() < currentTime; // Compare with current time

            if (isExpired) {
                console.log('Token is expired');
                res.json({ valid: false, message: "Invalid Token. Please generate a new token " });
                
            } else {
                console.log('Token is valid');
                res.json({ valid: true, message: "Invalid Token. Please generate a new token " });
                
            }
        }
     else {
        res.json({ valid: false, message: "Invalid Token. Please generate a new token " });
    }
})

app.post('/resetPassword',async (req,res)=>{
    const {token,password} = req.body
    const saltRounds = 10;

    bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        const query = "UPDATE users SET password=$1 WHERE token=$2;";

        try {
            const userResponse = await pool.query(query, [hash,token]);
            res.json({success:true})
        } catch (error) {
            console.error('Error inserting user:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
})

app.post('/check-auth', async (req, res) => {
    console.log("Cookies:", req.cookies);
    const token = req.cookies.authToken;

    if (!token) {
        console.log("You need to")
        return res.json({ login: "You need to" });
    }

    try {
        // Verify and decode the token to get user information
        const decoded = jwt.verify(token, "abcdefghijklmnnop");

        // Extract user details
        const userID = decoded.id; // Ensure this matches your token structure

        // Query to fetch goal macros from the database
        const query = `SELECT birthday,sex,goal_cals, goal_protein, goal_fats, goal_carbs FROM users WHERE user_id = $1`;

        // Execute the query using pool.query
        console.log("LLAS");
        pool.query(query, [userID], (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ login: "No", message: "Database error" });
            }

            if (results.length === 0) {
                return res.json({ login: "No", message: "User not found" });
            }
            console.log("Database Query Results:", JSON.stringify(results, null, 2));
            // Extract goal macro values from results
            const { goal_cals, goal_protein, goal_fats, goal_carbs,birthday,sex } = results["rows"][0];
            console.log(goal_cals);
            return res.json({
                login: "Yes",
                id: userID,
                name: decoded.name,
                iweight: decoded.i_weight,
                tweight: decoded.t_weight,
                cweight: decoded.c_weight,
                goal_cals: goal_cals,
                goal_protein: goal_protein,
                goal_fats: goal_fats,
                goal_carbs: goal_carbs,
                birthday: birthday,
                sex: sex
            });
        });

    } catch (err) {
        console.log("Invalid token");
        return res.json({ login: "No" });
    }
});

app.post('/add-food', async (req, res) => {
    console.log(req.body);
    const {id,date,name,ingredients,calories,servings,proteins,fats,carbs} = req.body
    console.log(id,date,name,ingredients,calories)
    const query = "INSERT INTO meals (meal_name,ingredients,proteins,fats,carbs,total_calories,date,user_id,servings) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)";
    const userResponse = await pool.query(query, [name,ingredients,proteins,fats,carbs,calories,date,id,servings]);
    return res.json({ add: "Yes"});
});

app.post('/save-recipe', async (req, res) => {
    
    const {id,name,ingredients,calories,fats,proteins,carbs} = req.body
    console.log(proteins)
    console.log(fats)
    const query = "INSERT INTO saved_recipes (meal_name,ingredients,calories,fats,proteins,carbs,user_id) VALUES($1,$2,$3,$4,$5,$6,$7)";
    const userResponse = await pool.query(query, [name,ingredients,calories,fats,proteins,carbs,id]);
    return res.json({ add: "Yes"});
});

app.post('/get-calories-saved-recipes', async (req, res) => {
    
    const { id,timezone } = req.body;
  
    const query = `
    SELECT 
        SUM(total_calories) AS total_calories, 
        SUM(proteins) AS total_proteins, 
        SUM(carbs) AS total_carbs, 
        SUM(fats) AS total_fats 
    FROM meals 
    WHERE user_id = $1 
        AND date = (NOW() AT TIME ZONE $2)::date
`;
    const userResponse = await pool.query(query, [id,timezone]);

    const { total_calories, total_proteins, total_carbs, total_fats } = userResponse.rows[0];
    const query2 = "SELECT meal_name,saved_recipe_id,ingredients,calories,proteins,fats,carbs FROM saved_recipes WHERE user_id = $1 ORDER BY saved_recipe_id DESC"
    const userResponse2 =  await pool.query(query2, [id]);
    const recipes = userResponse2.rows.map((row, index) => ({
        id: index + 1,
        saved_recipe_id: row.saved_recipe_id,
        name: row.meal_name,
        ingredients: row.ingredients,
        calories: row.calories,
        proteins: row.proteins,
        carbs: row.carbs,
        fats: row.fats
      }));
    const query3 = "SELECT date, SUM(total_calories) AS total_calories FROM meals WHERE user_id = $1 AND date >= CURRENT_DATE - INTERVAL '30 days' GROUP BY date ORDER BY date"
    const userResponse3 = await pool.query(query3, [id]);
    const calorieChartData = generateCaloriesForLast30Days(userResponse3.rows)
    const query4 = "SELECT date, weight FROM weight WHERE user_id = $1 AND date >= CURRENT_DATE - INTERVAL '30 days' ORDER BY date"
    const userResponse4 = await pool.query(query4, [id]);

    const weightChartData = generateWeightsForLast30Days(userResponse4.rows)
    const query5 = "SELECT current_weight FROM users WHERE user_id = $1"
    const userResponse5 = await pool.query(query5, [id]);
  
    
    tempRecipe = {...recipes}
    for( const recipe in tempRecipe){
        tempRecipe[recipe]["ingredients"] = tempRecipe[recipe]["ingredients"].split(",");
    }
      
    tempRecipe = Object.values(tempRecipe)
    return res.json({ add: "Yes", calories: total_calories,fats:total_fats,proteins: total_proteins,carbs: total_carbs, srecipes: recipes, cchart: calorieChartData ,wchart: weightChartData,weight:userResponse5.rows[0].current_weight,trecipe: tempRecipe });
});

app.post('/handle-quick-addmeal', async (req, res) => {
    const { search } = req.body;
 
    const result = await searchFoods({ search_expression: `${search}`, max_results: 20 });
    console.log(result)
    const filteredFood = result["foods"].food.filter(item => {
        const description = item.food_description.toLowerCase();
        return description.startsWith("per 1 serving") || description.startsWith("per 1 ");
      });
    
    
    if (filteredFood.length > 0) {
    const firstFood = filteredFood[0];
    const { food_description, calories, fat, carbs, protein } = firstFood;
  
    // Extract values from description (using regex for flexibility)
    const match = food_description.match(/Per 1 (.*?) Calories: (\d+)kcal \| Fat: (\d+\.\d+)g \| Carbs: (\d+\.\d+)g \| Protein: (\d+\.\d+)g/i);
  
    if (match) {
      const servingSize = match[1];
      const caloriesValue = parseInt(match[2]);
      const fatValue = parseFloat(match[3]);
      const carbsValue = parseFloat(match[4]);
      const proteinValue = parseFloat(match[5]);
  
      return res.json({ add: "Yes", calories: caloriesValue, fats: fatValue,carbs:carbsValue,protein:proteinValue });
  
      // You can further process these values here, e.g., store them in variables
    } else {
      console.error(`Could not parse calories and nutrients from description: ${food_description}`);
    }
  }
});

app.post('/get-chatgpt-meal-plan-specific', async (req, res) => {
    const {meal,description} = req.body
    try {
        console.log("reach");
        // Set up the prompt to send to ChatGPT
        const prompt1 = `
            I'm looking for a ${description} ${meal} !
            No matter what it says above!
            Format it in the following way! Give only one answer and do not include anything apart from the details below.Do not include units
            I want highly accurate calorie count based on all ingredients you suggest!!! Do not round off the calories. Give me a precise and very accurate amount
            name: The name of the dish.
            Ingredients: A list of main ingredients with accurate measurements with units.Return a list separated by commas
            Calories: Give me highly accurate calorie count by summing the calories of each ingredient suggested!!! This is very crucial and important. (no units) 
            Protein: Give me highly accurate protein count in grams(no units) 
            Fats: Give me highly accurate fat count in grams(no units) 
            Carbs: Give me highly accurate carbs count in grams(no units) 
        `;
        /*
        const prompt2 = `
            Make me a 150 gram 2700 kcal meal planner gluten free.
            Format it in the following way! Give only one answer and do not include anything apart from the details below.Do not include units g and kcal are assumed.
            Breakfast Name: The name of the dish.
            Calories:
            Protein:
            Fats:
            Carbs:
            Ingredients:
            Repeat above 5 lines 3 times with Lunch , Dinner , Snack.
        `;
        const prompt3 = `
        Make a vegetarian and dairy free meal plan for me.
        Format it in the following way! Give only one answer and do not include anything apart from the details below.Do not include units g and kcal are assumed.
        Day of the Week: 
        Breakfast Name: The name of the dish.
        Calories:
        Protein:
        Fats:
        Carbs:
        Ingredients:
        Repeat above 5 lines 3 times with Lunch , Dinner , Snack .
        I need this for all 7 days of the week.
    `   */
        // Call OpenAI's API
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a nutritionist and meal planner." },
                    { role: "user", content: prompt1 }
                ],
                max_tokens: 1500,  // Adjust based on desired output length
                temperature: 0.7  // Adjust based on creativity desired
            },
            {
                headers: {
                    'Authorization': `Bearer ${openaiApiKey}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        // Extract ChatGPT's response
        const mealPlan = response.data.choices[0].message.content;
        
        const mealInfo = ((text) => {
            const info = {};
        
            // Use regular expressions to match each field
            const nameMatch = text.match(/name:\s*(.+)/);
            const caloriesMatch = text.match(/Calories:\s*(\d+)/);
            const ingredientsMatch = text.match(/Ingredients:\s*(.+)/);
            const proteinMatch = text.match(/Protein:\s*(\d+)/);
            const fatsMatch = text.match(/Fats:\s*(\d+)/);
            const carbsMatch = text.match(/Carbs:\s*(\d+)/);
        
            // Assign matched groups to the info object if they exist
            info.name = nameMatch ? nameMatch[1].trim() : null;
            info.calories = caloriesMatch ? parseInt(caloriesMatch[1]) : null;
            info.protein = proteinMatch ? parseInt(proteinMatch[1]) : null;
            info.fats = fatsMatch ? parseInt(fatsMatch[1]) : null;
            info.carbs = carbsMatch ? parseInt(carbsMatch[1]) : null;
            
            // Add the type field after calories
            info.type = "quick";
            
            // Add ingredients if found
            info.ingredients = ingredientsMatch ? ingredientsMatch[1].trim().split(', ') : [];
        
            return info;
        })(mealPlan);
        
        console.log(mealInfo)

        res.status(200).json({
            success: true,
            mealPlan: mealInfo
        });
        
    } catch (error) {
        console.error("Error generating meal plan:", error.response?.data || error.message);
        res.status(500).json({
            success: false,
            message: "Could not generate meal plan"
        });
    }
})



app.post('/get-chatgpt-meal-plan-weekly', async (req, res) => {
    const { meal, description, calories, fats, carbs, protein,cuisine,preferredFoods,preferredFoodPercentage,excludedFoods,type,day } = req.body;

   
    async function generateMealFromOpenAI(calories, protein, fats, carbs, mealNo,day,setToString) {
        console.log(calories);
        console.log(protein)
        console.log(fats);
        console.log(carbs);
        console.log("JSDalkDAKS");
        const randomNumber = Math.floor(Math.random() * 100) + 1;
        foodChoice = "anything"
        setToString = Array.from(setToString).join(', ');
        console.log(setToString);
  
        if (randomNumber <= preferredFoodPercentage){
            rand = Math.floor(Math.random() * preferredFoods.length);
            foodChoice = preferredFoods[rand]
            console.log(foodChoice)
        }
        console.log(foodChoice)
        const prompt = `You are part of a weeklyMealPlan making program. Your work is to return one meal requested in the desired way.
        You will be given an update of meals you have already provided for the week and a description of what meal number it is.
        Make sure to assign the meal carefully using description, calories, protein, fats described. Keep in mind the dietary restrictions for particular days.
    
        User wants to have ${foodChoice} for this meal.
        The user prefers ${cuisine} cuisine. They
        If choice for this meal is anything, make sure you are not generating one of 
        ${excludedFoods.join(',')} or one of already generated for today ${setToString}.
        Generate a meal that should have ${calories} calories, with ${protein}g protein, ${fats}g fats, and ${carbs}g carbs.
        Ensure a highly accurate caloric and macro breakdown for each ingredient, while staying within calorie and macro ranges.

        Do not return anything extra except for the format requested below.
        Return ingredients separated by commas as shown below. If scaling is done, do not mention it in the output!
        Do NOT include caloric or macro totals in output. Format should be strictly followed!!!
        Do not include units with macro and cal breakdown per ingredient.
        Return the meal in the format:
        name: Meal Name
        Ingredients: quantity Ingredient 1(calories,carbs,protein,fats), quantity Ingredient 2(calories,carbs,protein,fats), ...
        `;
    
    
        try {
            const response = await axios.post(
                'https://api.openai.com/v1/chat/completions',
                {
                    model: "gpt-4o-mini",  // Ensure the correct model is used
                    messages: [
                        { role: "system", content: "You are a nutritionist and meal planner." },
                        { role: "user", content: prompt }
                    ],
                    max_tokens: 8000,  // Adjust based on desired length of response
                    temperature: 0.9  // Adjust creativity
                },
                {
                    headers: {
                        'Authorization': `Bearer ${openaiApiKey}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
            
            const mealResponse = response.data.choices[0].message.content;
            console.log(mealResponse);
            return mealResponse;
        } catch (error) {
            console.error("Error generating meal with OpenAI:", error.message);
            throw new Error("Could not generate meal");
        }
    }

    // Function to parse the OpenAI meal response
    function parseMealResponse(mealResponse) {
        // Initialize object to hold the parsed data
        const meal = {
            name: '',
            ingredients: [],
            totalCalories: 0,
            totalProtein: 0,
            totalFats: 0,
            totalCarbs: 0
        };
    
        // Regex to extract the meal name and ingredients
        const mealNameMatch = mealResponse.match(/^name:\s*(.+?)\s*Ingredients:/);
        if (mealNameMatch) {
            meal.name = mealNameMatch[1].trim();  // Get meal name
        }
    
        const ingredientsPart = mealResponse.split("Ingredients:")[1]; // Get ingredients part
    
        // Updated regex to correctly capture ingredients and their macros (calories, carbs, protein, fats),
        // allowing for optional units like 'g' and flexible space handling
        const ingredientRegex = /([\d\/\s]+[a-zA-Z\s]+)\s*\(?\s*(\d+(\.\d+)?),\s*(\d+(\.\d+)?),\s*(\d+(\.\d+)?),\s*(\d+(\.\d+)?)\)?/g;
        let match;
    
        // Extract each ingredient name and its macros, then calculate totals
        while ((match = ingredientRegex.exec(ingredientsPart)) !== null) {
            const ingredientName = match[1].trim(); // Get the ingredient name
            const calories = parseFloat(match[2]); // Get the calories
            const carbs = parseFloat(match[4]); // Get the carbs
            const protein = parseFloat(match[6]); // Get the protein
            const fats = parseFloat(match[8]); // Get the fats
    
            // Add to total meal macros
            meal.totalProtein += protein;
            meal.totalCarbs += carbs;
            meal.totalFats += fats;
            meal.totalCalories += protein*4+carbs*4+fats*9;
            
            meal.ingredients.push(ingredientName);
        }
    
        return meal;
    }
    
    
    // Function to calculate macros for a single meal
    function calculateMacrosForMeal(mealCalories, totalCalories, totalProtein, totalFats, totalCarbs) {
        const proteinPercent = totalProtein / totalCalories;
        const fatsPercent = totalFats / totalCalories;
        const carbsPercent = totalCarbs / totalCalories;
    
        const mealProtein = mealCalories * proteinPercent;
        const mealFats = mealCalories * fatsPercent;
        const mealCarbs = mealCalories * carbsPercent;
    
        return {
            calories: mealCalories,
            protein: Math.round(mealProtein),
            fats: Math.round(mealFats),
            carbs: Math.round(mealCarbs)
        };
    }

    // Function to generate a dynamic meal plan for a single day
    async function generateDynamicMealPlan(totalCalories, totalProtein, totalFats, totalCarbs,day,totalSet) {
        const minCalories = 350;
        const maxCalories = 700;
        const meals = [];
        let remainingCalories = totalCalories;
        let remainingProtein = totalProtein;
        let remainingFats = totalFats;
        let remainingCarbs = totalCarbs;
        let meal = 1
        const mySet = new Set()
        // While calories are still left to be allocated
        while (remainingCalories > 0) {
            const mealCalories = remainingCalories > 350 
                ? Math.min(remainingCalories, Math.floor(Math.random() * (maxCalories - minCalories + 1)) + minCalories)
                : remainingCalories;
    
            const mealMacros = {
                calories: mealCalories,
                protein: mealCalories*totalProtein/4,
                fats: mealCalories*totalFats/9,
                carbs: mealCalories*totalCarbs/4
            }
            console.log(mealMacros);
            
            const mealResponse = await generateMealFromOpenAI(mealMacros.calories, mealMacros.protein, mealMacros.fats, mealMacros.carbs,meal,day, mySet);
            
            // Parse OpenAI's response into structured data
            const parsedMeal = parseMealResponse(mealResponse);
            
            if (parsedMeal.ingredients.length > 0 && parsedMeal.totalCalories > 70){
                // Push the meal with actual macros (from OpenAI) to the meals array
                meals.push({
                    meal: parsedMeal.name,
                    ingredients: parsedMeal.ingredients,
                    calories: Math.round(parsedMeal.totalCalories),
                    protein: Math.round(parsedMeal.totalProtein),
                    fats: Math.round(parsedMeal.totalFats),
                    carbs: Math.round(parsedMeal.totalCarbs)
                });

                mySet.add(parsedMeal.name);
            }
            
             // Decrease the remaining calories/macros using OpenAI's actual macros
             remainingCalories -= parsedMeal.totalCalories;
     
             console.log("-----------------");
             console.log(remainingCalories);
             console.log("-----------------");

            meal += 1
            
        }
        return [meals,totalSet];
    }
    // Function to generate a 7-day meal plan
    async function generateWeeklyMealPlan(totalCalories, totalProtein, totalFats, totalCarbs) {
        const weeklyMealPlan = [];
        var totalSet = new Set()
        const map = {
            1: "Monday",
            2: "Tuesday",
            3: "Wednesday",
            4: "Thursday",
            5: "Friday",
            6: "Saturday",
            7: "Sunday"
        };
        // Loop through each day of the week (Day 1 to Day 7)
        for (let day = 1; day <= 7; day++) {
            console.log(`Generating meal plan for Day ${day}...`);
            
            const dailyMealPlan = await generateDynamicMealPlan(totalCalories, totalProtein, totalFats, totalCarbs,map[day],totalSet);
            
            // Create daily plan object (add date for clarity)
            const dailyPlan = {
                date: `${map[day]}`, // You can modify this to use actual day names like "Monday", "Tuesday", etc.
                meals: dailyMealPlan[0].map(meal => ({
                    name: meal.meal, // Meal name (e.g., "Breakfast", "Lunch", etc.)
                    ingredients: meal.ingredients, // List of ingredients
                    calories: meal.calories, // Total calories for the meal
                    protein: meal.protein, // Total protein for the meal
                    type: "quick",
                    fats: meal.fats, // Total fats for the meal
                    carbs: meal.carbs, // Total carbs for the meal
                }))
            };
            totalSet = dailyMealPlan[1]
            
            weeklyMealPlan.push(dailyPlan);
        }
        return weeklyMealPlan;
    }

    try {
        // Call to generate the weekly meal plan
        if (type == "weekly"){
            let proteinRatio = protein*4/calories
            let fatsRatio= fats*9/calories
            let carbsRatio = carbs*4/calories
            const arr = await generateWeeklyMealPlan(calories ?? 2000, proteinRatio, fatsRatio, carbsRatio);
            console.log(JSON.stringify(arr, null, 2));
            // Send a successful response
            res.status(200).json({
                success: true,
                message: "Meal plan successfully generated.",
                meal: arr // Return the generated meal plan in the response
            });
        }
        else if (type == "daily"){
            const map = {
                0: "Monday",
                1: "Tuesday",
                2: "Wednesday",
                3: "Thursday",
                4: "Friday",
                5: "Saturday",
                6: "Sunday"
            };
            let proteinRatio = protein*4/calories
            let fatsRatio= fats*9/calories
            let carbsRatio = carbs*4/calories
            
            const dailyMealPlan = await generateDynamicMealPlan(calories ?? 2000, proteinRatio , fatsRatio , carbsRatio ,"Monday",new Set());
            const dailyPlan = {
                date: map[day], // You can modify this to use actual day names like "Monday", "Tuesday", etc.
                meals: dailyMealPlan[0].map(meal => ({
                    name: meal.meal, // Meal name (e.g., "Breakfast", "Lunch", etc.)
                    ingredients: meal.ingredients, // List of ingredients
                    calories: meal.calories, // Total calories for the meal
                    protein: meal.protein, // Total protein for the meal
                    type: "quick",
                    fats: meal.fats, // Total fats for the meal
                    carbs: meal.carbs, // Total carbs for the meal
                }))
            };
            console.log(dailyPlan);
            res.status(200).json({
                success: true,
                message: "Meal plan successfully generated.",
                meal: dailyPlan // Return the generated meal plan in the response
            });

        }
        else{
            
        }
    } catch (error) {
        console.error("Error generating weekly meal plan:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to generate meal plan.",
            error: error.message
        });
    }
});
app.post('/set-meal-plan', async (req, res) => {
    const map = {
        0: "Monday",
        1: "Tuesday",
        2: "Wednesday",
        3: "Thursday",
        4: "Friday",
        5: "Saturday",
        6: "Sunday"
    };

    const { userID, weeklyPlan } = req.body;
    console.log(weeklyPlan);
    try {
        // Clear existing meal plan for user_id = 1
        await pool.query("DELETE FROM mealplan WHERE user_id = $1", [userID]);

        // Insert new plan
        for (let i = 0; i < weeklyPlan.length; i++) {
            const day = map[i];
            const meals = weeklyPlan[i]?.meals || [];

            for (const meal of meals) {
                const query = `
                    INSERT INTO mealplan (
                        meal_name, 
                        day, 
                        calories, 
                        protein, 
                        fats, 
                        carbs, 
                        ingredients,
                        user_id
                    ) VALUES (
                         $1, $2, $3, $4, $5, $6, $7,$8
                    )
                `;

                const roundedCalories = Math.floor(meal.calories || 0);
                const roundedProtein = Math.floor(meal.protein || 0);
                const roundedFats = Math.floor(meal.fats || 0);
                const roundedCarbs = Math.floor(meal.carbs || 0);

                const values = [
                    meal.name,
                    day,
                    roundedCalories,
                    roundedProtein,
                    roundedFats,
                    roundedCarbs,
                    JSON.stringify(meal.ingredients),
                    userID
                ];

                await pool.query(query, values);
            }
        }

        res.status(200).json({
            success: true,
            message: "Meal plan successfully saved."
        });
    } catch (error) {
        console.error("Error saving meal plan:", error.message);
        res.status(500).json({
            success: false,
            message: "Could not save meal plan."
        });
    }
});


app.post('/get-meal-plan', async (req, res) => {
    
    const {userID} = req.body

    const map = {
        "Monday": 0,
        "Tuesday": 1,
        "Wednesday": 2,
        "Thursday": 3,
        "Friday": 4,
        "Saturday": 5,
        "Sunday": 6
    };

    const mealPlanner = [
        { date: "Monday", meals: [] },
        { date: "Tuesday", meals: [] },
        { date: "Wednesday", meals: [] },
        { date: "Thursday", meals: [] },
        { date: "Friday", meals: [] },
        { date: "Saturday", meals: [] },
        { date: "Sunday", meals: [] }
    ];

    const query = `
        SELECT meal_id, meal_name, meal_type, day, calories, protein, fats, carbs, ingredients 
        FROM mealplan 
        WHERE user_id = $1
    `;
    const values = [userID];

    try {
        // Execute the query with parameterized values to prevent SQL injection
        const result = await pool.query(query, values);

        // Iterate over the query result and populate the mealPlanner object
        for (const row of result.rows) {
            const dayIndex = map[row.day];
            mealPlanner[dayIndex].meals.push({
                id: parseInt(row.meal_id),
                name: row.meal_name,
                ingredients: JSON.parse(row.ingredients),
                calories: parseInt(row.calories),
                protein: parseInt(row.protein),
                type: "quick",
                fats: parseInt(row.fats),
                carbs: parseInt(row.carbs),
                
            });
        }

        const prefs = await pool.query("SELECT goal_carbs,goal_cals,goal_protein,goal_fats FROM users WHERE user_id=$1", values);
        console.log("skadasdaklaklmskla");
        const { goal_carbs, goal_cals, goal_protein, goal_fats } = prefs.rows[0];
        const data = {
            carbs:goal_carbs,
            fats:goal_fats,
            protein:goal_protein,
            calories:goal_cals
        }
        console.log(mealPlanner)
        return res.json({ meal: mealPlanner,prefs:data });
    } catch (error) {
        console.error('Error fetching meal plan:', error);
        return res.status(500).json({ error: 'Failed to fetch meal plan' });
    }
})

app.post('/add-weight', async (req, res) => {
    const { id, weight, date } = req.body;
    console.log("hi");
    try {
        // Check if a record exists for the given user_id and date
        const checkQuery = "SELECT * FROM weight WHERE user_id = $1 AND date = $2";
        const existingRecord = await pool.query(checkQuery, [id, date]);

        if (existingRecord.rowCount > 0) {
            // If record exists, update the weight
            const updateQuery = "UPDATE weight SET weight = $1 WHERE user_id = $2 AND date = $3";
            await pool.query(updateQuery, [weight, id, date]);
        } else {
            // If no record exists, insert a new one
            const insertQuery = "INSERT INTO weight (user_id, date, weight) VALUES ($1, $2, $3)";
            await pool.query(insertQuery, [id, date, weight]);
        }

        // Retrieve the latest weight for the user, ordered by date (most recent first)
        const latestWeightQuery = `
            SELECT weight 
            FROM weight 
            WHERE user_id = $1 
            ORDER BY date DESC 
            LIMIT 1
        `;
        const latestWeightResult = await pool.query(latestWeightQuery, [id]);

        if (latestWeightResult.rowCount > 0) {
            const latestWeight = latestWeightResult.rows[0].weight;

            // Update the user's current_weight with the latest weight
            const updateUserWeightQuery = "UPDATE users SET current_weight = $1 WHERE user_id = $2";
            await pool.query(updateUserWeightQuery, [latestWeight, id]);
        }

        // Respond to the client
        return res.json({ success: true, message: "Weight updated successfully." });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "An error occurred." });
    }
});

app.post('/get-meals', async (req, res) => {
    try {
      const { user_id } = req.body;
      if (!user_id) {
        return res.status(400).json({ error: 'user_id is required' });
      }
  
      // Query to get meals grouped by date for the given user_id with date as string
      const mealsQuery = `
      SELECT 
      TO_CHAR(date, 'YYYY-MM-DD') AS date, -- Convert date to string format
      JSON_AGG(JSON_BUILD_OBJECT(
        'id',meal_id,
        'meal_name', meal_name,
        'total_calories', total_calories,
        'ingredients', ingredients,
        'proteins', proteins,
        'fats', fats,
        'carbs', carbs,
        'servings', servings
      )) AS meals
    FROM meals
    WHERE user_id = $1
    GROUP BY date
    ORDER BY date DESC;
      `;
  
      const { rows } = await pool.query(mealsQuery, [user_id]);
      console.log(rows);
      res.json({
        success: true,
        data: rows, // Array of meals grouped by date
      });
    } catch (err) {
      console.error('Error fetching meals:', err);
      res.status(500).json({ error: 'An error occurred while fetching meals' });
    }
  });
  
  app.post('/delete-logged-meal', async (req, res) => {
    try {
      const { id } = req.body;
      console.log(id)
      // Query to get meals grouped by date for the given user_id with date as string
      const mealsQuery = `DELETE FROM meals WHERE meal_id = $1;
      `;
  
      const { rows } = await pool.query(mealsQuery, [id]);
      res.json({
        success: true,
      });
    } catch (err) {
      console.error('Error fetching meals:', err);
      res.status(500).json({ error: 'An error occurred while fetching meals' });
    }
  });
  
  app.post('/delete-saved-meal', async (req, res) => {
    try {
      const { id } = req.body;
      console.log(id)
      // Query to get meals grouped by date for the given user_id with date as string
      const mealsQuery = `DELETE FROM saved_recipes WHERE saved_recipe_id = $1;
      `;
  
      const { rows } = await pool.query(mealsQuery, [id]);
      res.json({
        success: true,
      });
    } catch (err) {
      console.error('Error fetching meals:', err);
      res.status(500).json({ error: 'An error occurred while fetching meals' });
    }
  });
  
  app.post('/delete-mealplan-meal', async (req, res) => {
    try {
      const { id,meal_id } = req.body;

      // Query to get meals grouped by date for the given user_id with date as string
      const mealsQuery = `DELETE FROM mealplan WHERE user_id = $1 AND meal_id = $2;
      `;
  
      const { rows } = await pool.query(mealsQuery, [id,meal_id]);
      res.json({
        success: true,
      });
    } catch (err) {
      console.error('Error fetching meals:', err);
      res.status(500).json({ error: 'An error occurred while fetching meals' });
    }
  });

  app.post('/update-goals', async (req, res) => {
    try {
      const { id,goal,value } = req.body;
      let mealsQuery;
        console.log(goal);
        console.log(value);
      if( goal == "calories"){
        mealsQuery = `UPDATE users SET goal_cals = $1 WHERE user_id = $2;`
      }
      else if( goal == "protein"){
        mealsQuery = `UPDATE users SET goal_protein = $1 WHERE user_id = $2;`
      }
      else if( goal == "fats"){
        mealsQuery = `UPDATE users SET goal_fats = $1 WHERE user_id = $2;`
      }
      else if( goal == "carbs"){
        mealsQuery = `UPDATE users SET goal_carbs = $1 WHERE user_id = $2;`
      }
      else if( goal == "targetWeight"){
        mealsQuery = `UPDATE users SET target_weight = $1 WHERE user_id = $2;`
      }
      else if( goal == "currentWeight"){
        mealsQuery = `
            UPDATE users
            SET current_weight = $1,
                initial_weight = $1
            WHERE user_id = $2;
            `;
      }
      else if( goal == "lifestyle"){
        mealsQuery = `UPDATE users SET lifestyle = $1 WHERE user_id = $2;`
      }
      else if( goal == "goals"){
        mealsQuery = `UPDATE users SET goals = $1 WHERE user_id = $2;`
      }
      else if( goal == "height"){
        mealsQuery = `UPDATE users SET height = $1 WHERE user_id = $2;`
      }

  
      const { rows } = await pool.query(mealsQuery, [value,id]);
      const  r = await pool.query("SELECT goal_protein,goal_carbs,goal_fats FROM users WHERE user_id = $1", [id]);
      const calories = r.rows[0].goal_protein*4 + r.rows[0].goal_carbs*4 + r.rows[0].goal_fats*9
      await pool.query("UPDATE users SET goal_cals = $1 WHERE user_id = $2;", [calories,id]);
      res.json({
        success: true,
        calories: calories
      });
    } catch (err) {
      console.error('Error fetching meals:', err);
      res.status(500).json({ error: 'An error occurred while fetching meals' });
    }
  });

  app.post('/get-current-settings', async (req, res) => {
    try {
        const { id } = req.body;
        let mealsQuery = `SELECT height,lifestyle,goals,current_weight,target_weight, goal_cals, goal_protein, goal_fats, goal_carbs FROM users WHERE user_id = $1`;

        const { rows } = await pool.query(mealsQuery, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const userSettings = {
            "currentWeight": rows[0].current_weight,
            "targetWeight": rows[0].target_weight,
            "height": rows[0].height,
            "lifestyle": rows[0].lifestyle,
            "goals": rows[0].goals,
            "calories": rows[0].goal_cals,
            "protein": rows[0].goal_protein,
            "fats": rows[0].goal_fats,
            "carbs": rows[0].goal_carbs
        };

        res.json({
            success: true,
            settings: userSettings
        });

    } catch (err) {
        console.error('Error fetching settings:', err);
        res.status(500).json({ error: 'An error occurred while fetching settings' });
    }
});

app.post('/change-email', async (req, res) => {

    try {
        const { newEmail, oldEmail, userID } = req.body;
        

        // Check if the old email and userID combination exists
        const checkUserQuery = "SELECT user_id FROM users WHERE user_id = $1 AND email = $2";
        const { rows } = await pool.query(checkUserQuery, [userID, oldEmail]);

        if (rows.length === 0) {
            return res.status(200).json({ message: "Incorrect Old Email" });
        }

        // Check if the new email is already in use
        const checkNewEmailQuery = "SELECT user_id FROM users WHERE email = $1";
        const emailCheck = await pool.query(checkNewEmailQuery, [newEmail]);

        if (emailCheck.rows.length > 0) {
            return res.status(200).json({ message: "New email is already in use" });
        }

        // Update email
        const updateEmailQuery = "UPDATE users SET email = $1 WHERE user_id = $2 AND email = $3";
        await pool.query(updateEmailQuery, [newEmail, userID, oldEmail]);

        res.status(200).json({ message: "Email updated successfully" });

    } catch (err) {
        console.error('Error updating email:', err);
        res.status(500).json({ error: 'An error occurred while updating email' });
    }
});

app.post('/change-password', async (req, res) => {
    try {
        const { userID, oldPassword, newPassword } = req.body;

        // Retrieve the user's current password hash
        const userQuery = "SELECT password FROM users WHERE user_id = $1";
        const { rows } = await pool.query(userQuery, [userID]);

        const storedPassword = rows[0].password;

        // Compare old password with stored hash
        const isMatch = await bcrypt.compare(oldPassword, storedPassword);
        if (!isMatch) {
            console.log("Ds")
            return res.status(200).json({ message: "Incorrect Old Password" });
        }

        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the password in the database
        const updateQuery = "UPDATE users SET password = $1 WHERE user_id = $2";
        await pool.query(updateQuery, [hashedPassword, userID]);

        res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
        console.error('Error updating password:', err);
        res.status(500).json({ error: 'An error occurred while updating password' });
    }
});
app.post('/log-out', async (req, res) => {
    res.cookie('authToken', '', {
        httpOnly: true,
        maxAge: 0, // Set the maxAge to 0 to expire the cookie immediately
        secure: true, // Set to true if using HTTPS
        sameSite: 'None', // Ensure this matches the setting you used when the cookie was set
        path: '/' // Cookie is accessible from all paths
    });
    res.status(200).json({ message: "Cookie Removed" });
});

app.listen(port, () => {
    console.log(`Server is running on https://localhost:${port}`);
});





