const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const fs = require('fs');
const session = require('express-session');
const methodOverride = require('method-override');
const fileUpload = require('express-fileupload');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const passport = require('passport');
const flash = require('connect-flash');
const MongoDBSession = require('connect-mongodb-session')(session);
const moment = require('moment');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');

// for pdf viewing(receipt purposes)
const pdfThumbnail = require('pdf-thumbnail');

// functions
async function generatePdfThumbnail(pdfPath, thumbnailPath) {
    try {
        // Generate thumbnail
        const thumbnail = await pdfThumbnail(pdfPath, { width: 300 });

        // Save the thumbnail to disk
        fs.writeFileSync(thumbnailPath, thumbnail);
    } catch (error) {
        console.error('Error generating PDF thumbnail:', error);
    }
}

async function insertMonthlyBillPayment() {
    const currentDate = new Date();
    const currentMonth = moment(currentDate).format('MMMM'); // e.g., "January"
    const currentYear = currentDate.getFullYear();

    // Proceed only if today is the 1st day of the month
    if (currentDate.getDate() !== 1) {
        console.log('Not the 1st of the month, skipping automaton.');
        return;
    }

    try {
        // Fetch the "Yuran" product for the current month
        const yuranProduct = await Product.findOne({ 
            name: `Yuran ${currentMonth} ${currentYear}`, 
            type: 'yuran' 
        });

        if (!yuranProduct) {
            console.error('Yuran product not found for the current month.');
            return;
        }

        // Get all children and loop through them to check payments
        const children = await Child.find();

        for (let child of children) {
            // Check if a BillPayment record exists for the student in the current year
            let billPayment = await BillPayment.findOne({ 
                student_id: child._id, 
                year: currentYear 
            });

            // If no payment record exists for this month, insert into the order table
            if (!billPayment || !billPayment.payments.get(currentMonth)) {
                // Check if the order already exists for this child for the current month
                const existingOrder = await Order.findOne({
                    childId: child._id,
                    'products.name': `Yuran ${currentMonth} ${currentYear}`
                });

                if (!existingOrder) {
                    // Create a new order for the unpaid month
                    const newOrder = new Order({
                        orderId: new mongoose.Types.ObjectId().toString(),
                        childId: child._id,
                        products: [{
                            productId: yuranProduct._id,
                            name: `Yuran ${currentMonth} ${currentYear}`,
                            type: 'yuran',
                            price: yuranProduct.price
                        }],
                        totalAmount: yuranProduct.price,
                        invoiceNumber: `INV-${currentYear}-${new mongoose.Types.ObjectId().toString().substr(0, 6)}`,
                        status: 'Pay Now',
                        orderDate: new Date()
                    });

                    await newOrder.save();
                    console.log(`Order created for ${child.name} (${currentMonth} ${currentYear})`);
                }
            } else {
                console.log(`Payment already made for ${child.name} in ${currentMonth}`);
            }
        }

        console.log('Monthly bill payment insertion completed.');
    } catch (error) {
        console.error('Error in inserting monthly bill payment:', error);
    }
}

// Schedule this function to run daily at midnight or any preferred time
const schedule = require('node-schedule');
const job = schedule.scheduleJob('0 0 * * *', insertMonthlyBillPayment); // Runs every day at midnight

// Create the Yuran product for each month, or have it created manually in advance
async function createMonthlyYuranProduct() {
    const currentMonth = moment().format('MMMM');
    const currentYear = new Date().getFullYear();
    
    const existingProduct = await Product.findOne({ 
        name: `Yuran ${currentMonth} ${currentYear}` 
    });

    if (!existingProduct) {
        const yuranProduct = new Product({
            name: `Yuran ${currentMonth} ${currentYear}`,
            description: `Yuran bulanan untuk ${currentMonth} ${currentYear}`,
            price: 50, // Set a default price or configure as needed
            type: 'yuran'
        });

        await yuranProduct.save();
        console.log(`Yuran product for ${currentMonth} ${currentYear} created.`);
    }
}

// Schedule product creation at the end of the previous month
const productJob = schedule.scheduleJob('0 0 28-31 * *', createMonthlyYuranProduct); // Adjust date for non-leap February
// end of functions

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// set up express session
const sessionDatabase = mongoose.createConnection('mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/session');
const mongoURI = 'mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/session';
const store = new MongoDBSession({
    uri: mongoURI,
    collection: 'sessions',
    stringify: false,
    connection: sessionDatabase
});

// Configure session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    store: store,
    cookie: {
        maxAge: 7 * 60 * 60 * 1000
    }
}));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

app.use(fileUpload());
app.use(methodOverride('_method'));

// Middleware to expose user in locals
app.use((req, res, next) => {
    res.locals.user = req.user;
    next();
});
app.use(flash());

// Middleware to make flash messages available to templates
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});
app.use(async (req, res, next) => {
    try {
      const settings = await Settings.findOne(); // Fetch the settings only once
      app.locals.settings = settings; // Store it globally
    } catch (error) {
      console.error("Error fetching settings:", error);
    }
    next();
});

// MongoDB Connection
// const userDB = mongoose.createConnection(
//     'mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/user'
// );
// const teacherDB = mongoose.createConnection(
//     'mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/teacher'
// );
// const fileDB = mongoose.createConnection(
//     'mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/fileuploaded'
// );
const detailDB = mongoose.createConnection(
    'mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/detail'
);
// const productDB = mongoose.createConnection(
//     'mongodb+srv://hfzdnedu:KQkRnx4dehRxqZ40@itary.uitcp.mongodb.net/products'
// );

// Define schema for child, parent, teacher, and file
const childSchema = new mongoose.Schema({
    name: String,
    dob: Date,
    ic_no: String,  
    gender: String,  
    tempat_lahir: String,  
    keturunan: String,  
    warganegara: String,  
    pribumi_sarawak: String,
    propict: String,  
    class_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: false },
    receiptUploaded: { type: Boolean, default: false },
    parent_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Parent' },
    attendanceRecords: [{
        date: Date,
        status: String,  
        additionalInfo: String
    }],
    siblings: [{
        nama: String,
        dob: Date,
        status: { type: String, enum: ['Masih Belajar', 'Bekerja', 'Tidak Bekerja'] },
        tahap_pendidikan: { type: String, enum: ['Prasekolah', 'Pendidikan Rendah', 'Pendidikan Menengah', 'Pendidikan Pra-Universiti', 'Pengajian Tinggi'] }
    }]
});

const classSchema = new mongoose.Schema({
    classname: String,
    teachersincharge: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Teacher' }],
});

const userSchema = new mongoose.Schema({
    firstname: String,
    lastname: String,
    username: String,
    email: { type: String, required: true, index: true, unique: true },
    password: String,
    role: { type: String, enum: ['parent', 'teacher', 'admin'], required: true },
    nama_bapa: String,
    ic_no_bapa: String,
    warganegara_bapa: String,
    phone_bapa: String,
    pekerjaan_bapa: String,
    nama_ibu: String,
    ic_no_ibu: String,
    pekerjaan_ibu: String,
    warganegara_ibu: String,
    phone_ibu: String,
    phone: String,
    subject: String,
    address: String,
});

const parentSchema = new mongoose.Schema({
    user_id:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    children:  [{ type: mongoose.Schema.Types.ObjectId, ref: 'Child' }]
});

const teacherSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    class_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: true }
});

const fileSchema = new mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child', required: true },
    filePath: String,
    originalName: String,
    thumbnailPath: String,
    uploadDate: { type: Date, default: Date.now }
});

const attendanceSchema = new mongoose.Schema({
    student_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Child', required: true },
    status: { type: String, enum: ['HADIR', 'TIDAK HADIR'], required: true },
    additional_info: { type: String },
    date: { type: Date, required: true }
});

const paymentSchema = new mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child'}, 
    products: [{
        name: String,
        desc: String,
        type: { type: String },
        color: String,
        size: { type: String },
        quantity: { type: Number, default: 1 },
        price: Number
    }],
    isProduct: { type: Boolean },
    totalAmount: { type: Number }, 
    date: { type: Date, default: Date.now }, 
    timestamp: { type: Date, default: Date.now },
    file: String,
    status: { type: String, enum: ['Pay Now', 'Pending', 'Paid', 'Invalid'] } 
});

const eventSchema = new mongoose.Schema({
    title: String,
    start: Date,
    end: Date,
});

const settingsSchema = new mongoose.Schema({
    carouselImages: [{
        imageUrl: String,
        caption: String,
        description: String
    }],
    headerColor: { type: String },
    new:  { type: Boolean, default: false},
    upsert: {type: Boolean, default: false}

});

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Passport Local Strategy
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            // First, try to find the user in the User table
            let user = await User.findOne({ username });

            if (user) {
                // User found in User table
                const isMatch = await bcrypt.compare(password, user.password);
                if (isMatch) return done(null, user);
                return done(null, false, { message: 'Incorrect password.' });
            }

            // If not found, try to find the user in the Parent table
            const parent = await Parent.findOne({ username });
            if (parent) {
                // Parent found in Parent table
                const isMatch = await bcrypt.compare(password, parent.password);
                if (isMatch) return done(null, parent);
                return done(null, false, { message: 'Incorrect password.' });
            }

            // If neither user nor parent found
            return done(null, false, { message: 'Incorrect username.' });
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, { id: user._id.toString(), type: user.role || 'parent' });
});

passport.deserializeUser(async (sessionData, done) => {
    try {
        const { id, type } = sessionData;
        let user;

        if (type === 'admin' || type === 'teacher') {
            user = await User.findById(id);
        } else if (type === 'parent') {
            user = await Parent.findById(id);
        }

        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const Teacher = detailDB.model('Teacher', teacherSchema);
const Child = detailDB.model('Child', childSchema);
const Parent = detailDB.model('Parent', parentSchema);
const File = detailDB.model('File', fileSchema);
const Attendance = detailDB.model('Attendance', attendanceSchema);
const User = detailDB.model('User', userSchema);
const Class = detailDB.model('Class', classSchema);
const Payment = detailDB.model('Payment', paymentSchema);
const Event = detailDB.model('Event', eventSchema);
const Settings = detailDB.model('Settings', settingsSchema);

async function calculateAttendanceSummary() {
    const currentDate = new Date(); // Get current local date

    // Convert to UTC to match MongoDB's stored date format
    const startOfDay = new Date(Date.UTC(currentDate.getUTCFullYear(), currentDate.getUTCMonth(), currentDate.getUTCDate(), 0, 0, 0));
    const endOfDay = new Date(Date.UTC(currentDate.getUTCFullYear(), currentDate.getUTCMonth(), currentDate.getUTCDate(), 23, 59, 59, 999));

    const attendanceRecords = await Attendance.find({
        date: { $gte: startOfDay, $lt: endOfDay }
    }).exec();

    // Fetch all children to map their student_id to class_id
    const children = await Child.find({}, 'class_id _id').exec();
    const childClassMap = new Map(children.map(child => [child._id.toString(), child.class_id]));

    // Fetch all class information
    const classes = await Class.find().exec();

    const attendanceSummary = classes.map(cls => {
        const age = parseInt(cls.classname.charAt(0)); 
        const classType = cls.classname.split(' ')[1];

        // Filter attendance records for this class
        const studentsInClass = children.filter(child => child.class_id.equals(cls._id));
        const totalStudents = studentsInClass.length;

        const classAttendance = attendanceRecords.filter(record => {
            const classId = childClassMap.get(record.student_id.toString());
            return classId && classId.equals(cls._id); // Check if the child's class matches the current class
        });

        const presentStudents = classAttendance.filter(record => record.status === 'HADIR').length;

        const attendancePercentage = totalStudents > 0 ? (presentStudents / totalStudents) * 100 : 0;

        return {
            classType,
            age,
            attendancePercentage,
            totalStudents // Include total students in the summary
        };
    });

    return attendanceSummary;
}

// const { Child,  Teacher, Parent, Order, BillPayment, Product, Class, File, Attendance, User } =  require('./models');

// Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

// Render the login page or redirect based on user role
app.get('/', async (req, res) => {
    if (req.session && req.session.user) {
        try {
            const userId = req.session.user.id;
            let user = await User.findById(userId);
            if (!user) {
                let teacher = await Teacher.findById(userId);
                if (!teacher) {
                    let parent = await Parent.findById(userId);
                    if (!parent) {
                        req.flash('error', 'User not found');
                        return res.redirect('/login');
                    } else {
                        user = parent;
                    }
                } else {
                    user = teacher;
                }
            }

            if (!user) {
                req.flash('error_msg', 'User not found');
                return res.redirect('/login');
            }

            return res.redirect('/dashboard');  // Redirect to dashboard based on session
        } catch (error) {
            console.error('Error during login redirect:', error);
            req.flash('error_msg', 'Internal Server Error');
            return res.redirect('/login');
        }
    } else {
        // Render login page if not logged in
        res.render('login', {
            logoPath: '/img/image.png',
            validationUsername: '',
            validationPassword: '',
            username: '',
            password: '',
            toastShow: '',
            toastMsg: '' // Ensure flash messages are passed to the view
        });
    }
});

app.get('/login', (req, res) => { 
    res.render('login', { 
        logoPath: '/img/image.png', 
        validationUsername: '', 
        validationPassword: '', 
        username: '', 
        password: '', 
        toastShow: '', 
        toastMsg: '' 
    }); 
}).post('/sign-in', async (req, res, next) => { 
    const { username, password, rememberMe } = req.body;

    console.time('Sign-in Process');

    const expirationDate = rememberMe
        ? moment().utcOffset(8).add(7, 'days').toDate()
        : moment().utcOffset(8).add(1, 'hour').toDate();

    try {
        // Check in the User table
        let user = await User.findOne({ username });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            // Invalid username or password
            req.flash('error_msg', 'Invalid username or password');
            return res.render('login', {
                validationUsername: 'is-valid',
                validationPassword: 'is-invalid',
                username,
                password,
                toastShow: 'show',
                toastMsg: 'Incorrect username or password',
                logoPath: '/img/image.png'
            });
        }

        // Set session and role-based redirection
        req.session.user = {
            id: user._id.toString(),
            role: user.role
        };

        console.timeEnd('Sign-in Process');
        req.flash('success_msg', 'You are now logged in');
        return res.redirect('/dashboard');
        
    } catch (error) {
        console.error('Error:', error);
        next(error);
    }
});

app.post('/logout', async (req, res, next) => {
    try {
        // Clear the session
        req.session = null;

        // Clear the cookies
        res.clearCookie('connect.sid');

        // Redirect to home
        res.redirect('/');
    } catch (error) {
        // Handle any unexpected errors
        console.error('Error:', error);
        next(error);
    }
});

// Render the login page or redirect based on user role
app.get('/dashboard', async (req, res) => {
    if (!req.session || !req.session.user) {
        return res.redirect('/'); // Redirect to login if not authenticated
    }

    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        let parent;

        if (userRole === 'parent') {
            parent = await Parent.findOne({ user_id: userId });
        }

        // Fetch user based on ID
        const user = await User.findById(userId);
        if (!user) return res.redirect('/login');

        // Fetch global carousel images
        const settings = await Settings.findOne({});
        const carouselImages = settings ? settings.carouselImages : [];

        // Date-related variables
        const currentMonthIndex = new Date().getMonth();
        const currentYear = new Date().getFullYear();
        const currentMonthName = new Intl.DateTimeFormat('default', { month: 'long' }).format(new Date(currentYear, currentMonthIndex));

        let events = []; // Initialize events array
        let totalPaidAmount = 0; // Initialize total paid amount

        // Role-based logic
        if (userRole === 'parent') {
            // Fetch children for parent
            const children = await Child.find({ parent_id: parent._id });
            const childIds = children.map(child => child._id);

            // Fetch payments for the current month
            const payments = await Payment.find({
                childId: { $in: childIds },
                date: { $gte: new Date(currentYear, currentMonthIndex, 1), $lt: new Date(currentYear, currentMonthIndex + 1, 1) }
            }).populate('childId', 'name');

            // Format payments and calculate total paid amount
            const formattedPayments = payments.map(payment => {
                totalPaidAmount += payment.totalAmount; // Sum up total amount for all payments

                const dueDate = new Date(payment.date);
                dueDate.setDate(dueDate.getDate() + 7); // Add 7 days for payment due date

                // Get product names
                const productNames = payment.products.map(product => product.name).join(', '); // Join product names

                // Determine status class
                const statusClass = {
                    'Paid': 'text-success',
                    'Pending': 'text-warning',
                    'Expired': 'text-danger',
                    'Pay Now': 'text-primary'
                }[payment.status] || 'text-primary'; // Default to 'text-primary'

                return {
                    _id: payment._id,
                    studentName: payment.childId ? payment.childId.name : 'Unknown',
                    productName: productNames, // Include product names here
                    date: payment.date.toISOString().split('T')[0],
                    dueDate: dueDate.toISOString().split('T')[0],
                    amount: payment.totalAmount.toFixed(2),
                    status: payment.status,
                    statusClass
                };
            });

            return res.render('dashboard', {
                user,
                invoices: formattedPayments, // Renamed to invoices for consistency
                totalPaidAmount,
                currentMonthName,
                events,
                carouselImages
            });

        } else {
            // For admin/teacher
            const studentCount = await Child.countDocuments({});
            const teacherCount = await Teacher.countDocuments({});

            // Fetch events for the calendar (assuming an Event model)
            events = await Event.find({});

            // Calculate total amount for paid payments in the current month
            const paidPayments = await Payment.find({
                status: 'Paid',
                date: { $gte: new Date(currentYear, currentMonthIndex, 1), $lt: new Date(currentYear, currentMonthIndex + 1, 1) }
            });
            totalPaidAmount = paidPayments.reduce((sum, payment) => sum + payment.totalAmount, 0);

            // Fetch attendance summary (assuming a utility function exists)
            const attendanceSummary = await calculateAttendanceSummary();

            return res.render('dashboard', {
                user,
                studentCount,
                teacherCount,
                attendanceSummary,
                events,
                totalPaidAmount,
                currentMonthName,
                carouselImages
            });
        }

    } catch (err) {
        console.error("Error fetching data:", err);
        return res.status(500).send("Internal Server Error");
    }
});

// Profile Display
// Get Profile Page
app.get('/profile', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // For teacher, get additional class information
        if (userRole === 'teacher') {
            const classes = await Class.find({ teachersincharge: user._id });
            user.classInCharge = classes.map(cls => ({ _id: cls._id, className: cls.classname }));
        }

        res.render('profile-display', { user, userRole });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Failed to fetch profile information');
        res.redirect('/');
    }
});


// Update Profile
app.post('/edit-profile/admin', async (req, res) => {
    try {
        const { username, email } = req.body;
        const adminId = req.session.user.id;

        await User.findByIdAndUpdate(adminId, {
            username,
            email
        });

        req.flash('success', 'Profile updated successfully');
        res.redirect('/profile');
    } catch (err) {
        console.error('Error updating admin profile:', err);
        res.status(500).send('Error updating profile');
    }
});

app.post('/edit-profile/teacher', async (req, res) => {
    try {
        const { username, firstname, lastname, email, phone, subject, classInCharge } = req.body;
        const teacherId = req.session.user.id;

        await Teacher.findByIdAndUpdate(teacherId, {
            username,
            firstname,
            lastname,
            email,
            phone,
            subject,
            class_id: classInCharge
        });

        req.flash('success', 'Profile updated successfully');
        res.redirect('/profile');
    } catch (err) {
        console.error('Error updating admin profile:', err);
        res.status(500).send('Error updating profile');
    }
});

app.post('/edit-profile/parent', async (req, res) => {
    try {
        const { username, email, fatherIC, fatherCitizenship, fatherOccupation, fatherPhone, motherName,
            motherIC, motherCitizenship, motherOccupation, motherPhone
         } = req.body;
        const parentId = req.session.user.id;

        await Parent.findByIdAndUpdate(parentId, {
            username: username,
            email: email,
            ic_no_bapa: fatherIC,
            warganegara_bapa: fatherCitizenship,
            phone_bapa:  fatherPhone,
            pekerjaan_bapa: fatherOccupation,
            nama_ibu: motherName,
            ic_no_ibu: motherIC,
            warganegara_ibu: motherCitizenship,
            pekerjaan_ibu: motherOccupation,
            phone_ibu: motherPhone
        });

        req.flash('success', 'Profile updated successfully');
        res.redirect('/profile');
    } catch (err) {
        console.error('Error updating admin profile:', err);
        res.status(500).send('Error updating profile');
    }
});

// Get Class Details model
app.get('/class-details/:classId', async (req, res) => {
    try {
        const classId = req.params.classId;
        const classData = await Class.findById(classId).populate('students');

        if (!classData) {
            return res.json({ success: false, message: 'Class not found' });
        }

        res.json({
            success: true,
            className: classData.classname,
            students: classData.students.map(student => ({
                name: student.name,
                dob: student.dob.toDateString() // Adjust date format if needed
            }))
        });
    } catch (error) {
        console.error(error);
        res.json({ success: false, message: 'Failed to fetch class details' });
    }
});


// Render the student registration form (assuming it's for parents)
// Handle student registration form submission and redirect to parent registration
app.post('/register-student', async (req, res) => {
    try {
        const userId = req.session.user.id;
        // Get the parent's ID from the session
        const parent = await Parent.findOne({user_id: userId});
        const parentId = parent._id;

        // Extract student details from the form submission
        const { childName, ic_no, gender, childdob, tempat_lahir, keturunan, warganegara, pribumi_sarawak, class_id } = req.body;

        // Create a new Child document
        const newChild = new Child({
            name: childName,
            dob: childdob,
            gender: gender,
            ic_no: ic_no,
            tempat_lahir: tempat_lahir,
            keturunan: keturunan,
            warganegara: warganegara,
            pribumi_sarawak: pribumi_sarawak,
            parent_id: parentId // Link the parent's ID to the child
        });

        // Conditionally add class_id to the newChild object
        if (class_id) {
            newChild.class_id = class_id;
        }

        // Check for other children with the same parent_id
        const existingSiblings = await Child.find({ parent_id: parentId });

        // If there are existing siblings, add the new child to their siblings list
        if (existingSiblings.length > 0) {
            const newSiblingInfo = {
                nama: newChild.name,
                dob: newChild.dob,
                status: 'Masih Belajar', // Assuming they are still studying by default
                tahap_pendidikan: 'Pendidikan Rendah' // Default education level, can be modified
            };

            // Update each existing sibling's document with the new child's info
            for (let sibling of existingSiblings) {
                sibling.siblings.push(newSiblingInfo);
                await sibling.save();

                // Add each existing sibling to the new child's siblings list
                newChild.siblings.push({
                    nama: sibling.name,
                    dob: sibling.dob,
                    status: 'Masih Belajar', // Assuming default status
                    tahap_pendidikan: 'Prasekolah' 
                });
            }
        }

        const savedChild = await newChild.save();

        await Parent.findByIdAndUpdate(parentId, {
            $push: {children: savedChild._id}
        });

        res.redirect('/table');
    } catch (err) {
        console.error('Error registering student', err);
        res.status(500).send('Error registering student');
    }
});

// Render the student registration form (assuming it's for parents)
app.get('/register-student', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Get the parent's ID from the session
        const parentId = req.session.user.id;

        // Get all registered classes
        const registeredClasses = await Class.find().populate('teachersincharge');

        // Render the student registration form with the parent's ID and registered classes
        res.render('children', { registeredClasses, parentId, user });
    } catch (err) {
        console.error('Error retrieving class data', err);
        res.status(500).send('Error retrieving class data');
    }
});

// Render the parent registration form
app.get('/register-parent', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if(!userId || !userRole){
            return res.redirect('/');
        }

        const user = await User.findById(userId);;

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        res.render('parent', { user });
    } catch (err) {
        console.error('Error retrieving classes from the database', err);
        res.status(500).send('Error retrieving classes from the database');
    }
});

// Handle parent registration and save both child and parent data
app.post('/register-parent', async (req, res) => {
    const { fathername, mothername, emailparent, usernameparent, parentpass, confirmPass } = req.body;

    try {
        // Check if passwords match
        if (parentpass !== confirmPass) {
            return res.status(400).send('Passwords do not match.');
        }

        // Validate email
        if (!emailparent || emailparent.trim() === '') {
            return res.status(400).send('Email cannot be empty.');
        }

        // Check if the email already exists in the User collection
        const existingUser = await User.findOne({ email: emailparent });
        if (existingUser) {
            return res.status(400).send('Email already registered.');
        }

        // Create new parent user
        const newParentUser = new User({
            nama_bapa: fathername,
            nama_ibu: mothername,
            username: usernameparent,
            email: emailparent, // Ensure this is being set
            password: await bcrypt.hash(parentpass, 10), // Hash the password
            role: 'parent'  // Assign role as parent
        });

        const savedParentUser = await newParentUser.save();

        const newParent = new Parent({
            user_id: savedParentUser._id,
        });

        // Save the new parent
        await newParent.save();

        // Redirect to the parent table page
        res.redirect('/table-parent');
    } catch (error) {
        console.error('Error registering parent:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to render the teacher registration form
app.get('/register-teacher', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Fetch classes with fewer than 2 teachers in charge
        const classData = await Class.find().populate('teachersincharge');
        const availableClasses = classData.filter(cls => cls.teachersincharge.length < 2);

        res.render('teacher', { availableClasses, user });
    } catch (err) {
        console.error('Error retrieving classes from the database', err);
        res.status(500).send('Error retrieving classes from the database');
    }
});

// Handle teacher registration form submission
app.post('/register-teacher', async (req, res) => {
    const { teacherName, teacherfirstName, teacherEmail, teacherPhone, teacherPass, confirmPass, teacherClass } = req.body;

    try {
        // Check if passwords match
        if (teacherPass !== confirmPass) {
            return res.status(400).send('Passwords do not match.');
        }

        // Check if the email already exists
        const existingUser = await User.findOne({ email: teacherEmail });
        if (existingUser) {
            return res.status(400).send('Email already registered.');
        }

        // Create new teacher user
        const newTeacherUser = new User({
            firstname: teacherfirstName,
            username: teacherName,
            email: teacherEmail,
            phone: teacherPhone,
            password: await bcrypt.hash(teacherPass, 10), // Hash the password
            role: 'teacher'  // Assign role as teacher
        });

        // Save the new teacher's user data
        const savedTeacherUser = await newTeacherUser.save();

        // Save the teacher's information in the Teacher schema
        const newTeacher = new Teacher({
            user_id: savedTeacherUser._id,
            class_id: teacherClass
        });
        await newTeacher.save();

        // Update the class with the teacher's ID
        await Class.findByIdAndUpdate(teacherClass, { 
            $push: { teachersincharge: newTeacher._id } 
        });

        // Redirect to the teacher table page
        res.redirect('/table-guru');
    } catch (error) {
        console.error('Error registering teacher:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Teacher Class Registration (self-registration)
app.post('/register-class', async (req, res) => {
    const { classname, teacherId } = req.body;

    try {
        const teacher = await Teacher.findById(teacherId);
        if (!teacher) {
            req.session.errorMessage = 'Teacher not found';
            return res.redirect('/register-class');
        }

        let selectedClass = await Class.findOne({ classname });
        if (!selectedClass) {
            selectedClass = new Class({ classname });
        }

        if (selectedClass.teachersincharge.length >= 2 && !selectedClass.teachersincharge.includes(teacherId)) {
            req.session.errorMessage = 'Class is already full of teachers';
            return res.redirect('/register-class');
        }

        const teacherAlreadyAssigned = await Class.findOne({ teachersincharge: teacherId });
        if (teacherAlreadyAssigned && !teacherAlreadyAssigned._id.equals(selectedClass._id)) {
            req.session.errorMessage = 'You are already assigned to another class';
            return res.redirect('/register-class');
        }

        if (!selectedClass.teachersincharge.includes(teacherId)) {
            selectedClass.teachersincharge.push(teacherId);
            await selectedClass.save();
        }

        teacher.class_id = selectedClass._id;
        await teacher.save();

        req.session.successMessage = 'You have successfully registered for the class';
        res.redirect('/register-class');
    } catch (error) {
        console.error('Error registering for class:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Admin assigning teachers to class
app.post('/admin-assign-class', async (req, res) => {
    const { classname, teacherId } = req.body;

    try {
        const teacher = await Teacher.findById(teacherId);
        if (!teacher) {
            req.session.errorMessage = 'Teacher not found';
            return res.redirect('/register-class');
        }

        let selectedClass = await Class.findOne({ classname });
        if (!selectedClass) {
            selectedClass = new Class({ classname });
        }

        if (selectedClass.teachersincharge.length >= 2 && !selectedClass.teachersincharge.includes(teacherId)) {
            req.session.errorMessage = 'Class is already full of teachers';
            return res.redirect('/register-class');
        }

        const teacherAlreadyAssigned = await Class.findOne({ teachersincharge: teacherId });
        if (teacherAlreadyAssigned && !teacherAlreadyAssigned._id.equals(selectedClass._id)) {
            req.session.errorMessage = 'This teacher is already assigned to another class';
            return res.redirect('/register-class');
        }

        if (!selectedClass.teachersincharge.includes(teacherId)) {
            selectedClass.teachersincharge.push(teacherId);
            await selectedClass.save();
        }

        teacher.class_id = selectedClass._id;
        await teacher.save();

        req.session.successMessage = 'Teacher assigned to class successfully';
        res.redirect('/register-class');
    } catch (error) {
        console.error('Error assigning teacher:', error);
        req.session.errorMessage = 'Internal Server Error';
        res.redirect('/register-class');
    }
});

// Parent Class Registration
app.post('/parent-assign-class', async (req, res) => {
    const { childId, class_id } = req.body;

    try {
        const child = await Child.findById(childId);
        if (!child) {
            req.session.errorMessage = 'Child not found';
            return res.redirect('/register-class');
        }

        const count = await Child.countDocuments({ class_id: class_id });
        if (count >= 25) {
            req.session.errorMessage = 'Class is already full';
            return res.redirect('/register-class');
        }

        child.class_id = class_id;
        await child.save();

        req.session.successMessage = 'Class assigned to your child successfully';
        res.redirect('/register-class');
    } catch (error) {
        console.error('Error assigning class:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Register Class GET Route
app.get('/register-class', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Fetch all class names
        const allClasses = ['4 Arif', '4 Bijak', '4 Cerdik', '5 Arif', '5 Bijak', '5 Cerdik', '6 Arif', '6 Bijak', '6 Cerdik'];

        // Get the count of children assigned to each class
        const classCounts = await Child.aggregate([
            { $group: { _id: '$class_id', count: { $sum: 1 } } }
        ]);

        // Map class IDs to their counts
        const classCountMap = classCounts.reduce((map, { _id, count }) => {
            map[_id] = count;
            return map;
        }, {});

        // Get available classes
        const availableClasses = await Class.find({}).populate('teachersincharge');

        // Add the student count to each class
        availableClasses.forEach(classItem => {
            classItem.studentCount = classCountMap[classItem._id] || 0;
        });

        // Fetch all teachers for admin view
        let allTeachers = [];
        if (userRole === 'admin') {
            allTeachers = await Teacher.find({}); // Fetch all teachers from the database
        }

        // Get messages from the session and clear them
        const successMessage = req.session.successMessage;
        const errorMessage = req.session.errorMessage;
        req.session.successMessage = null;
        req.session.errorMessage = null;

        // Render the view based on user role
        if (userRole === 'teacher' || userRole === 'admin') {
            res.render('register-class', {
                allClasses,
                availableClasses,
                allTeachers, // Pass the teachers to the view for admin
                userRole,
                user,
                successMessage,
                errorMessage
            });
        } else if (userRole === 'parent') {
            res.render('register-class', {
                availableClasses,
                userRole,
                user,
                children: user.children,
                successMessage,
                errorMessage
            });
        }
    } catch (error) {
        console.error('Error fetching class details:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/table', async (req, res) => {
    if (req.session && req.session.user) {
        try {
            const userId = req.session.user.id;
            const userRole = req.session.user.role;

            if (!userId || !userRole) {
                return res.redirect('/'); // Redirect to login if not authenticated
            }

            // Fetch logged-in user's details
            const user = await User.findById(userId);

            if (!user) {
                req.flash('error_msg', 'User not found');
                return res.redirect('/login');
            }

            const isParent = userRole === 'parent';
            const isAdmin = userRole === 'admin';

            let childrenData = [];

            if (isParent) {
                // Fetch parent details by user_id and populate child information
                const parent = await Parent.findOne({ user_id: userId });
                if (parent) {
                    childrenData = await Child.find({ parent_id: parent._id })
                        .populate({
                            path: 'parent_id',
                            model: 'Parent',
                            populate: {
                                path: 'user_id',
                                model: 'User', // Populate user details inside parent
                            },
                        })
                        .populate('class_id') // Populate class details
                        .lean();

                    // Fetch files for each child
                    for (let child of childrenData) {
                        const files = await File.find({ childId: child._id }); // Fetch files by child ID
                        child.files_info = files; // Attach the files to the child object
                    }
                }
            } else {
                // Fetch all children with their parent and class details for non-parent users
                childrenData = await Child.find({})
                    .populate({
                        path: 'parent_id',
                        model: 'Parent',
                        populate: {
                            path: 'user_id',
                            model: 'User', // Populate user details inside parent
                        },
                    })
                    .populate('class_id') // Populate class details
                    .lean();

                for (let child of childrenData) {
                    const files = await File.find({ childId: child._id }); // Fetch files by child ID
                    child.files_info = files; // Attach the files to the child object
                }
            }

            // Fetch all teachers with class information
            const teachers = await Teacher.find().populate('class_id').lean();

            // Fetch user information for each teacher and map by class_id
            const teacherIds = teachers.map(t => t.user_id); // Collect user_ids of teachers
            const teacherUsers = await User.find({ _id: { $in: teacherIds } }).lean();

            // Create a map to store teacher names by class_id
            const teachersByClassId = teachers.reduce((acc, teacher) => {
                const classIdStr = teacher.class_id ? teacher.class_id.toString() : null;
                if (classIdStr) {
                    const user = teacherUsers.find(u => u._id.equals(teacher.user_id));
                    if (user) {
                        if (!acc[classIdStr]) {
                            acc[classIdStr] = [];
                        }
                        acc[classIdStr].push(user.firstname + ' ' + (user.lastname || '')); // Store full name of teacher
                    }
                }
                return acc;
            }, {});

            // Add teacher names to child data based on class
            childrenData.forEach(child => {
                if (child.class_id) {
                    const classIdStr = child.class_id._id.toString();
                    child.teacherNames = teachersByClassId[classIdStr] ? teachersByClassId[classIdStr].join(', ') : 'No Teacher';
                } else {
                    child.teacherNames = 'No Class Assigned';
                }
            });

            // Fetch class data with populated teachers if needed
            const classes = await Class.find()
                .populate({
                    path: 'teachersincharge',
                    select: 'firstname', // Select only the firstname of teachers
                })
                .lean();

            // Add teacher names to class data
            for (let classData of classes) {
                classData.teachersinchargeNames = classData.teachersincharge
                    .map(teacher => teacher.firstname)
                    .join(', ');
            }
            
            // Render the table with the collected data
            res.render('table', {
                children: childrenData,
                isAdmin,
                classes,
                user,
            });
        } catch (err) {
            console.error('Error retrieving student data', err);
            res.status(500).send('Error retrieving student data');
        }
    } else {
        res.redirect('/'); // Redirect if session or user is not found
    }
});

app.get('/table-guru', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Fetch all teachers (users with the role 'teacher')
        const teachers = await User.find({ role: 'teacher' });

        // Fetch all classes and populate the teachersincharge field
        const classes = await Class.find().populate('teachersincharge');

        // Fetch all children to calculate the number of students per class
        const children = await Child.find().populate('class_id'); // Ensure we populate class info for each child

        // Process teacher information
        const teacherInfo = teachers.map(teacher => {
            // Find the class the teacher is in charge of
            const classInCharge = classes.find(cls => 
                cls.teachersincharge && cls.teachersincharge.some(t => t.user_id.equals(teacher._id))
            );

            // Calculate the number of students in that class
            const numOfStudents = classInCharge
                ? children.filter(child => child.class_id && child.class_id._id.toString() === classInCharge._id.toString()).length
                : 0;

            // Handle teachers with and without last names
            const name = teacher.lastname ? `${teacher.firstname} ${teacher.lastname}` : `${teacher.firstname}`;

            return {
                name,
                classInCharge: classInCharge ? classInCharge.classname : 'No Class Assigned',
                numOfStudents,
                phone: teacher.phone || 'No Phone Number',
                teacher: teacher
            };
        });

        res.render('table-guru', { teachers: teacherInfo, user });
    } catch (error) {
        console.error('Error fetching teacher and student information:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to get parents filtered by class
app.get('/table-parent', async (req, res) => { 
    try {
        const userId = req.session.user.id;      // Get logged-in user's ID
        const { selectedClass, selectedUnregisteredClass } = req.query; // Get selected class for filtering
        const userRole = req.session.user.role;  // Get user role (admin or teacher)

        let classes, unregisteredClasses;

        let user = await User.findById(userId);
        
        // Fetch the logged-in user (Teacher or Admin)
        if (userRole === 'teacher') {
            const teacher = await Teacher.findOne({ user_id: userId });
            if (!teacher) {
                return res.status(404).send('Teacher not found');
            }
            classes = await Class.find({ teachersincharge: teacher._id }).select('_id classname');
        } else if (userRole === 'admin') {
            classes = await Class.find().select('_id classname');
        } 

        // Fetch unregistered classes (no children assigned to these classes)
        unregisteredClasses = await Class.find({
            _id: { $nin: (await Child.find().distinct('class_id')) } // Classes without registered children
        }).select('_id classname');

        // Filter children based on selected class or unregistered class
        let filter = {};
        if (selectedClass) {
            filter.class_id = selectedClass;  // Filter children by selected registered class
        } else if (selectedUnregisteredClass) {
            filter.class_id = selectedUnregisteredClass;  // Filter children by selected unregistered class
        }

        const children = await Child.find(filter).populate('class_id');  // Populate class information
        
        // Fetch all parents based on the children found
        const parentIds = children.map(child => child.parent_id).filter(Boolean);
        const parents = await Parent.find({ _id: { $in: parentIds } });
        
        // Map parents to their children
        const parentMap = {};
        parents.forEach(parent => {
            parentMap[parent._id] = {
                ...parent._doc,  // Spread parent details
                children: []
            };
        });

        children.forEach(child => {
            if (child.parent_id && parentMap[child.parent_id]) {
                parentMap[child.parent_id].children.push({
                    name: child.name,
                    childId: child._id,
                    className: child.class_id?.classname
                });
            }
        });

        // Render the table-parent page
        res.render('table-parent', {
            parents: Object.values(parentMap),  // Convert parent map to an array
            classes,                           // Registered classes for the dropdown
            unregisteredClasses,               // Unregistered classes for the dropdown
            selectedClass,                     // The selected registered class for filtering
            selectedUnregisteredClass,         // The selected unregistered class for filtering
            user                               // Logged-in user information
        });
    } catch (error) {
        console.error('Error fetching parent data:', error);
        res.status(500).send('Server error');
    }
});

// ==== Student details =====
app.get('/student-details/:id', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Fetch child (student) details by ID
        const student = await Child.findById(req.params.id).populate('class_id');
        if (!student) {
            return res.status(404).send('Student not found');
        }

        // Fetch parent details using parent_id from child
        const parentData = await Parent.findById(student.parent_id);

        const parent = await User.findById(parentData.user_id);
        // Fetch class info and populate the teachers associated with the class
        const classInfo = await Class.findById(student.class_id).populate('teachersincharge');
        let teachers = [];
        if (classInfo) {
            teachers = classInfo.teachersincharge; // The populated field will now have teacher objects
        }

        // Fetch any files linked to this child
        const files = await File.find({ childId: student._id });

        // Combine all the details into one object
        const studentDetails = {
            ...student.toObject(), // Convert Mongoose document to plain object
            parent_info: parent || {}, // Include parent details if available
            teacher_info: teachers || [], // Include list of teachers if any
            class_info: classInfo || {}, // Include class information if available
            files_info: files || [], // Include list of files if any
        };

        const isAdmin = req.session.user && req.session.user.role === 'admin';

        // Render the student details page with the fetched data
        res.render('studentdetails', { student: studentDetails, isAdmin, user });
    } catch (err) {
        console.error('Error retrieving student details', err);
        res.status(500).send('Error retrieving student details');
    }
});

// Route to render teacher details
app.get('/teacher/:id', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const teacherId = req.params.id;

        // Find teacher by ID
        const teacher = await Teacher.findById(teacherId).exec();

        if (!teacher) {
            return res.status(404).send('Teacher not found');
        }

        // Render teacher details page
        // Determine if the current user is an admin
        const isAdmin = (req.session.user && req.session.user.role === 'admin');

        res.render('teacher-details', { teacher, isAdmin: isAdmin, user });
    } catch (err) {
        console.error('Error retrieving teacher details', err);
        res.status(500).send('Error retrieving teacher details');
    }
});

// Route to render parent details
app.get('/parent/:id', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const parentId = req.params.id;
        const parent = await Parent.findById(parentId); // Fetch parent data from the database
        
        if (parent) {
            // Determine if the current user is an admin
            const isAdmin = req.session.user && (req.session.user.role === 'admin' || req.session.user.role === "teacher");

            res.render('parent-details', { parent, isAdmin: isAdmin, user }); // Render the parent details page
        } else {
            res.status(404).send('Parent not found');
        }
    } catch (err) {
        console.error('Error retrieving parent data', err);
        res.status(500).send('Error retrieving parent data');
    }
});

// Route to render the edit student page
app.get('/edit-student/:id', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        // Fetch the current logged-in user
        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Fetch the student by childId and populate parent and user details
        const childId = req.params.id;
        const student = await Child.findById(childId)
        .populate({
            path: 'parent_id',  // Populate Parent details
            model: 'Parent',
            populate: {
                path: 'user_id', // Populate User details inside Parent
                model: 'User'
            }
        })
        .exec();

        if (!student) {
            return res.status(404).send('Student not found');
        }

        // Extract parent user details if available
        const parent = student.parent_id ? student.parent_id.user_id : null;

        // Render the edit page with student, parent, and user information
        res.render('edit-details', { student, parent, user });
    } catch (err) {
        console.error('Error retrieving student data', err);
        res.status(500).send('Error retrieving student data');
    }
});

// Route to handle the student update
app.post('/edit-student/:id', async (req, res) => {
    try {
        const childId = req.params.id;
        let profilePicturePath;
        
        const uploadDir = path.join(__dirname, 'uploads');

        // Check if a new profile picture was uploaded
        if (req.files && Object.keys(req.files).length > 0) {
            const profilePicture = req.files.propict;
            const profilePictureFilename = `${Date.now()}_${profilePicture.name}`; // Add a timestamp to the filename
            profilePicturePath = path.join(uploadDir, profilePictureFilename);

            // Save the file to the uploads directory
            profilePicture.mv(profilePicturePath, async (err) => {
                if (err) {
                    console.error('Error saving profile picture:', err);
                    req.flash('error_msg', 'Error uploading profile picture');
                    return res.redirect(`/edit-student/${childId}`);
                }
            });

            // Store the relative file path for saving in the database
            profilePicturePath = `/uploads/${profilePictureFilename}`;
        }

        // Extract student details from form
        const { 
            name, 
            ic_no, 
            gender, 
            dob, 
            tempat_lahir, 
            keturunan, 
            warganegara, 
            pribumi_sarawak, 
            class: newClass
        } = req.body;

        // Extract parent details from form
        const {
            nama_bapa, 
            ic_no_bapa, 
            pekerjaan_bapa,
            phone_bapa, 
            nama_ibu, 
            ic_no_ibu, 
            pekerjaan_ibu, 
            address, 
            phone_ibu,
            warganegara_bapa,
            warganegara_ibu
        } = req.body;

        // Update student information
        const updateData = {
            name,
            ic_no,
            gender,
            dob,
            tempat_lahir,
            keturunan,
            warganegara,
            pribumi_sarawak,
            class: newClass
        };

        // If a new profile picture was uploaded, update the profile picture path
        if (profilePicturePath) {
            updateData.propict = profilePicturePath;
        }

        // Update the child record with the new data
        const updatedChild = await Child.findByIdAndUpdate(childId, updateData, { new: true });

        const parent = await Parent.findById(updatedChild.parent_id);

        // Update parent information if the child has a parent
        if (updatedChild && parent.user_id) {
            await User.findByIdAndUpdate(parent.user_id, {
                nama_bapa,
                ic_no_bapa,
                pekerjaan_bapa,
                phone_bapa,
                nama_ibu,
                ic_no_ibu,
                pekerjaan_ibu,
                address,
                phone_ibu,
                warganegara_ibu,
                warganegara_bapa
            });
        }

        req.flash('success_msg', 'Student and parent details updated successfully');
        res.redirect(`/student-details/${childId}`);
    } catch (err) {
        console.error('Error updating student and parent data', err);
        req.flash('error_msg', 'Error updating student and parent data');
        res.status(500).send('Error updating student and parent data');
    }
});


// Route to render the edit teacher page
app.get('/edit-teacher/:id', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if(!userId || !userRole){
        return res.redirect('/');
        }

        let user;

        if (userRole === 'parent') {
            user = await Parent.findById(userId);
        } else if (userRole === 'teacher') {
            user = await Teacher.findById(userId);
        } else if (userRole === 'admin'){
            user = await User.findById(userId);
        }

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }
        const teacherId = req.params.id;

        // Find teacher by ID
        const teacher = await Teacher.findById(teacherId).exec();

        if (!teacher) {
            return res.status(404).send('Teacher not found');
        }

        // Get available classes for the edit form
        const allClasses = [
            "4 Arif", "4 Bijak", "4 Cerdik", "5 Arif", "5 Bijak", "5 Cerdik", "6 Arif", "6 Bijak", "6 Cerdik"
        ];

        res.render('editteacher', { teacher, allClasses, user });
    } catch (err) {
        console.error('Error retrieving teacher data', err);
        res.status(500).send('Error retrieving teacher data');
    }
});

// Handle teacher update
app.post('/edit-teacher/:id', async (req, res) => {
    try {
        const teacherId = req.params.id;
        const { name, email, phone, class: newClass } = req.body;

        // Update teacher information
        await Teacher.findByIdAndUpdate(teacherId, {
            name,
            email,
            phone,
            class: newClass
        });

        res.redirect('/table');
    } catch (err) {
        console.error('Error updating teacher data', err);
        res.status(500).send('Error updating teacher data');
    }
});

// Siblings information
app.get('/register-sibling/:id', async (req, res) => {
    try {
        const student = await Child.findById(req.params.id);
        if (!student) {
            return res.status(404).send('Student not found');
        }
        res.render('register-sibling', { student });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching student details');
    }
});

// Handle student deletion
app.post('/delete-student/:id', async (req, res) => {
    try {
        const childId = req.params.id;

        // Find the child to get the linked parent_id
        const child = await Child.findById(childId).exec();

        if (!child) {
            return res.status(404).send('Student not found');
        }

        // // Find the parent ID linked to this child
        // const parentId = child.parent_id;

        // Delete the student
        await Child.findByIdAndDelete(childId);

        // Delete the parent if it exists
        // if (parentId) {
        //     await Parent.findByIdAndDelete(parentId);
        // }

        res.redirect('/table');
    } catch (err) {
        console.error('Error deleting student and parent', err);
        res.status(500).send('Error deleting student and parent');
    }
});

// Handle teacher deletion
app.post('/delete-teacher/:id', async (req, res) => {
    try {
        const teacherId = req.params.id;

        // Delete teacher
        await Teacher.findByIdAndDelete(teacherId);

        res.redirect('/table');
    } catch (err) {
        console.error('Error deleting teacher', err);
        res.status(500).send('Error deleting teacher');
    }
});

// ====STUDENTS ATTENDANCE RECORD====

// Route to render the attendance page
app.get('/rekod-kehadiran', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        let user;
        let teacherClassId = null;

        if (userRole === 'parent') {
            user = await Parent.findById(userId);
        } else if (userRole === 'teacher') {
            user = await Teacher.findById(userId);
            if (user && user.class_id) {
                teacherClassId = user.class_id; // The class the teacher is in charge of
            }
        } else if (userRole === 'admin') {
            user = await User.findById(userId);
        }

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const { kelas, tarikh } = req.query;

        // Fetch all classes with their details
        const classes = await Class.find().exec();
        const currentDate = new Date();
        const selectedClass = kelas || teacherClassId || (classes.length > 0 ? classes[0]._id.toString() : '');
        const selectedDate = tarikh ? new Date(tarikh) : currentDate;

        // Fetch students based on class ID
        const students = await Child.find({ class_id: selectedClass }).exec();
        const attendanceRecords = await Attendance.find({
            student_id: { $in: students.map(student => student._id) },
            date: selectedDate
        }).exec();

        const attendanceMap = {};
        attendanceRecords.forEach(record => {
            attendanceMap[record.student_id] = record;
        });

        const isAdmin = req.session.user && req.session.user.role === 'admin';
        const isTeacher = req.session.user && req.session.user.role === 'teacher';

        res.render('rekodKehadiran', {
            students,
            classes,
            selectedClass,
            selectedDate: selectedDate.toISOString().split('T')[0],
            attendanceMap,
            isAdmin,
            isTeacher,
            teacherClassId,  // Send this to the view
            user
        });
    } catch (error) {
        console.error('Error fetching attendance records:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/rekod-kehadiran', async (req, res) => {
    try {
        const { kelas, tarikh } = req.body;

        // Find all students in the selected class
        const students = await Child.find({ class_id: kelas }).exec();

        // Convert the date to a Date object
        const selectedDate = new Date(tarikh);

        // Find attendance records for the selected class and date
        const attendanceRecords = await Attendance.find({
            student_id: { $in: students.map(student => student._id) },
            date: selectedDate
        }).exec();

        const attendanceMap = {};
        attendanceRecords.forEach(record => {
            attendanceMap[record.student_id] = record;
        });

        res.render('rekodKehadiran', {
            students,
            selectedClass: kelas,
            selectedDate: selectedDate.toISOString().split('T')[0],
            attendanceMap,
            isAdmin: req.session.user.role === 'admin'
        });
    } catch (error) {
        console.error('Error fetching attendance records:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/save-kehadiran', async (req, res) => {
    try {
        const { tarikh, kelas, records } = req.body;

        // Convert the date to a Date object
        const selectedDate = new Date(tarikh);

        // Process each record
        for (const record of records) {
            const { studentId, hadir, maklumatTambahan } = record;
            
            // Find or create an attendance record
            await Attendance.findOneAndUpdate(
                { student_id: studentId, date: selectedDate },
                { status: hadir, additional_info: maklumatTambahan },
                { upsert: true, new: true }
            );
        }

        req.flash('success_msg', 'Attendance records saved successfully');
        res.redirect(`/rekod-kehadiran?kelas=${kelas}&tarikh=${tarikh}`);
    } catch (error) {
        console.error('Error saving attendance records:', error);
        req.flash('error_msg', 'An error occurred while saving attendance records');
        res.redirect('/rekod-kehadiran');
    }
});

// ====FILE UPLOAD====

app.get('/receiptupload/:childId', async (req, res) => {
    const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if(!userId || !userRole){
        return res.redirect('/');
        }

        let user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

    const childId = req.params.childId;

    if (!mongoose.Types.ObjectId.isValid(childId)) {
        return res.status(400).send('Invalid child ID');
    }

    try {
        const child = await Child.findById(childId);
        if (!child) {
            return res.status(404).send('Child not found');
        }
        res.render('receiptupload', { child, user });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Handle file upload using `express-fileupload`
app.post('/upload-receipt', async (req, res) => {
    const childId = req.body.childId;

    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    let receiptFiles = req.files.receipt;
    if (!Array.isArray(receiptFiles)) {
        receiptFiles = [receiptFiles];
    }

    try {
        for (const receiptFile of receiptFiles) {
            const fileName = `${childId}-${Date.now()}${path.extname(receiptFile.name)}`;
            const uploadPath = path.join(uploadDir, fileName);

            await receiptFile.mv(uploadPath);

            const newFile = new File({
                childId: childId,
                filePath: `/uploads/${fileName}`,
                originalName: receiptFile.name
            });

            // Generate thumbnail for PDF files
            if (path.extname(receiptFile.name).toLowerCase() === '.pdf') {
                const thumbnailPath = path.join(uploadDir, `${fileName}-thumbnail.png`);
                await generatePdfThumbnail(uploadPath, thumbnailPath);

                // Save the thumbnail path in the database
                newFile.thumbnailPath = `/uploads/${path.basename(thumbnailPath)}`;
            }

            await newFile.save();
        }

        await Child.findByIdAndUpdate(childId, { receiptUploaded: true });
        res.redirect(`/receiptdetails/${childId}`);
    } catch (error) {
        console.error('Error saving file data to the database', error);
        res.status(500).send('Error saving file data.');
    }
});

// ====FILE VIEW====
app.get('/receiptdetails/:childId', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if(!userId || !userRole){
        return res.redirect('/');
        }

        let user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const childId = req.params.childId;
        const child = await Child.findById(childId).exec();

        if (!child) {
            return res.status(404).send('Child not found');
        }

        // Find all files associated with this child
        const files = await File.find({ childId: childId }).exec();

        const isAdmin = req.session.user && req.session.user.role === 'admin';

        // Render the view with file details
        res.render('receiptdetails', { files, childId, isAdmin, user });
    } catch (error) {
        console.error('Error fetching receipt:', error);
        res.status(500).send('Internal Server Error');
    }
});

// ====FILE DELETE====
app.delete('/delete-receipt/:fileId', async (req, res) => {
    try {
        const fileId = req.params.fileId;

        // Find the file by its ID
        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).send('File not found');
        }

        // Construct the absolute path to the file
        const filePath = path.join(__dirname, file.filePath); // Adjust __dirname if needed
        console.log(`Attempting to delete file at path: ${filePath}`);
        // Check if the file exists before attempting to delete
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        } else {
            console.warn(`File not found: ${filePath}`);
        }

        // Delete the file record from the database
        await File.findByIdAndDelete(fileId);

        // Check if there are any remaining files for the same child
        const remainingFiles = await File.find({ childId: file.childId });

        if (remainingFiles.length === 0) {
            // Update the corresponding Child document to indicate no receipt is uploaded
            await Child.findByIdAndUpdate(file.childId, { receiptUploaded: false });
        }

        res.redirect(`/receiptdetails/${file.childId}`);
    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Render the registration page
app.get('/register', (req, res) => {
    res.render('createaccount');
});

// Handle registration form submission
app.post('/register-account', async (req, res) => {
    try {
        const { username, email, password, confirmPassword, role } = req.body;

        // Check if passwords match
        if (password !== confirmPassword) {
            return res.status(400).send('Passwords do not match.');
        }

        // Validate role
        if (!['admin', 'teacher', 'parent'].includes(role)) {
            return res.status(400).send('Invalid role selected.');
        }

        // Check if email already exists in the User collection
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).send('Email already registered.');
        }

        // Create new user
        const newUser = new User({
            username,
            email,
            password: await bcrypt.hash(password, 10),  // Hash the password
            role,
        });

        await newUser.save();  // Save the new user

        res.redirect('/');  // Redirect to login or show a success message
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to render the bill payment tracker page
app.get('/bil-payment-tracker', async (req, res) => {
    const userId = req.session.user?.id;
    const userRole = req.session.user?.role;
    const selectedClass = req.query.kelas || '';
    const selectedMonth = parseInt(req.query.month) || new Date().getMonth() + 1;
    const classes = await Class.find({}); // Fetch all classes for admin

    if (!userId || !userRole) {
        return res.redirect('/');
    }

    const user = await User.findById(userId);

    if (!user) {
        req.flash('error_msg', 'User not found');
        return res.redirect('/');
    }

    let teacherClass = null;
    let students = [];

    if (userRole === 'teacher') {
        // Fetch the teacher's class details
        teacherClass = await Teacher.findOne({ user_id: user._id })
            .populate('class_id')
            .exec();

        if (teacherClass && teacherClass.class_id) {
            // Filter students by the teacher's assigned class
            students = await Child.find({ class_id: teacherClass.class_id._id });
        }
    } else if (userRole === 'parent') {
        // Parents can only see their own children
        const par = await Parent.findOne({user_id: userId});
        students = await Child.find({ parent_id: par._id });
    } else if (userRole === 'admin') {
        // Admin can filter students by class or fetch all students
        const filter = selectedClass ? { class_id: selectedClass } : {};
        students = await Child.find(filter);
    }

    // Filter orders for students by selected month
    const startDate = new Date(new Date().getFullYear(), selectedMonth - 1, 1);
    const endDate = new Date(new Date().getFullYear(), selectedMonth, 1);

    const orders = await Payment.find({
        childId: { $in: students.map(student => student._id) },
        date: { $gte: startDate, $lt: endDate }
    }).populate('childId');

    // Create a map of orders for quick access
    const ordersMap = {};
    orders.forEach(order => {
        const childId = order.childId._id.toString();
        if (!ordersMap[childId]) {
            ordersMap[childId] = [];
        }
        ordersMap[childId].push(order);
    });

    // Map students with their corresponding orders
    const updatedStudents = students.map(student => ({
        ...student.toObject(),
        orders: ordersMap[student._id.toString()] || []
    }));

    res.render('bilPaymentTracker', {
        teacherClass,
        selectedMonth,
        selectedClass,
        user,
        students: updatedStudents,
        classes
    });
});

app.post('/bil-payment-tracker', async (req, res) => {
    try {
        const { kelas, year } = req.body;

        const selectedYear = parseInt(year);

        // Validate the year
        if (isNaN(selectedYear)) {
            return res.status(400).send('Invalid year');
        }

        const students = await Child.find({ class: kelas }).exec();

        // Fetch payment records for the selected year
        const paymentRecords = await BillPayment.find({
            student_id: { $in: students.map(student => student._id) },
            year: selectedYear
        }).exec();

        // Create a payment map
        const paymentMap = {};
        paymentRecords.forEach(payment => {
            // Convert Map to plain object
            paymentMap[payment.student_id.toString()] = Object.fromEntries(payment.payments);
        });

        res.render('bilPaymentTracker', {
            students,
            classes: await Child.distinct('class'),
            selectedClass: kelas,
            selectedYear: year,
            paymentMap
        });
    } catch (error) {
        console.error('Error fetching payment records:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/save-bil-payments', async (req, res) => {
    try {
        const { payment, year } = req.body;
        const selectedYear = parseInt(year);

        // Validate the year
        if (isNaN(selectedYear)) {
            return res.status(400).send('Invalid year');
        }

        if (Array.isArray(payment)) {
            for (const record of payment) {
                const { studentId, payments } = record;

                // Convert string values to boolean
                const processedPayments = {};
                Object.keys(payments).forEach(key => {
                    processedPayments[key] = payments[key] === 'on';
                });

                if (Array.isArray(studentId)) {
                    for (const id of studentId) {
                        if (mongoose.Types.ObjectId.isValid(id)) {
                            const existingPayment = await BillPayment.findOne({ student_id: id, year: selectedYear });

                            if (existingPayment) {
                                existingPayment.payments = processedPayments;
                                await existingPayment.save();
                            } else {
                                await BillPayment.create({
                                    student_id: id,
                                    year: selectedYear,
                                    payments: processedPayments
                                });
                            }
                        } else {
                            console.warn(`Invalid studentId: ${id}`);
                        }
                    }
                } else if (mongoose.Types.ObjectId.isValid(studentId)) {
                    const existingPayment = await BillPayment.findOne({ student_id: studentId, year: selectedYear });

                    if (existingPayment) {
                        existingPayment.payments = processedPayments;
                        await existingPayment.save();
                    } else {
                        await BillPayment.create({
                            student_id: studentId,
                            year: selectedYear,
                            payments: processedPayments
                        });
                    }
                } else {
                    console.warn(`Invalid studentId: ${studentId}`);
                }
            }
        
            console.log('Bill payment records saved successfully');
            res.redirect(`/bil-payment-tracker?kelas=${req.body.kelas}&year=${year}`);
        } else {
            console.warn('Payment is not an array:', payment);
            res.status(400).send('Invalid data format');
        }
    } catch (error) {
        console.error('Error saving bill payment records:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/payment-summary', async (req, res) => {
    try {
        const userId = req.session.user?.id;
        const userRole = req.session.user?.role;
        const selectedYear = req.query.year || new Date().getFullYear(); // Use the selected year or the current year

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Fetch all classes
        const classes = await Class.find();

        // Fetch orders with the specified product_id, status 'Paid', and the selected year
        const product_id = '66f0c25fd8a4e6c64c1e1f8e';
        const paidOrders = await Payment.find({
            'products.productId': product_id,
            status: 'Paid',
            orderDate: {
                $gte: new Date(`${selectedYear}-01-01`),
                $lte: new Date(`${selectedYear}-12-31`)
            }
        }).populate('childId');

        // Prepare data to include student counts in each class
        const classData = await Promise.all(classes.map(async (classItem) => {
            const studentCount = await Child.countDocuments({ class_id: classItem._id });

            // Initialize the expectedPayments array with empty actualRM for each month
            const paymentsPerMonth = Array.from({ length: 12 }, (_, i) => ({
                month: new Date(0, i).toLocaleString('default', { month: 'long' }),
                expectedRM: studentCount * 450,
                actualRM: 0, // Initialize with 0 for each month
                variance: 0
            }));

            // Iterate over paid orders for this class and update the actualRM for the corresponding month
            paidOrders.forEach(order => {
                if (order.childId.class_id.equals(classItem._id)) {
                    const orderMonth = new Date(order.orderDate).getMonth(); // Get month as 0-11
                    paymentsPerMonth[orderMonth].actualRM += 450; // Add RM 450 for each paid order in that month
                }
            });

            return {
                _id: classItem._id,
                classname: classItem.classname,
                studentCount: studentCount,
                expectedPayments: paymentsPerMonth // Replace the expectedPayments with monthly breakdown
            };
        }));

        // Render the payment summary page with the class data and selected year
        res.render('payment-summary', { classes: classData, user, selectedYear });
    } catch (error) {
        console.error('Error fetching payment summary:', error);
        res.status(500).send('Internal Server Error');
    }
});

// ==== PRODUCTS PAYMENT ====
app.get('/product-page', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        const parent = await Parent.findOne({user_id: userId});

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const isTeacher = userRole === 'teacher';
        const isAdmin = userRole === 'admin';
        const isParent = userRole === 'parent';

        let children = [];
        if (isParent) {
            // Fetch the children for the parent if the user is a parent
            children = await Child.find({ parent_id: parent._id });
        }

        // Fetch only products where isProduct is true
        const products = await Payment.findOne({ isProduct: true });

        // Render the product-page template, passing the necessary data
        res.render('payment-page', {
            products: products.products,
            children,   // Pass the list of children for the parent
            isAdmin,
            isTeacher,
            isParent,
            user
        });
    } catch (err) {
        console.error('Error retrieving products or children', err);
        res.status(500).send('Error retrieving data');
    }
});

app.get('/add-product', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Render the add-product page
        res.render('add-product', { user });
    } catch (err) {
        console.error('Error rendering add-product page', err);
        res.status(500).send('Error rendering page');
    }
});

app.post('/add-product', async (req, res) => {
    const newProduct = {
        name: req.body.name,
        desc: req.body.description,
        type: req.body.type,
        color: req.body.color || '',
        size: req.body.size || '',
        quantity: req.body.quantity || null,
        price: req.body.price
    };
    
    try {
        // Find the existing payment document with isProduct: true
        const existingProducts = await Payment.findOne({ isProduct: true });

        if (existingProducts) {
            // Add the new product to the existing products array
            existingProducts.products.push(newProduct);
            await existingProducts.save();

            res.redirect('/product-page');
        } else {
            const newProduct = new Payment({
                products: [{
                    name: req.body.name,
                    desc: req.body.description,
                    type: req.body.type,
                    color: req.body.color,
                    size: req.body.size,
                    quantity: req.body.quantity,
                    price: req.body.price
                }],
                isProduct: true // Mark this entry as a product
            });
    
            await newProduct.save();
            res.redirect('/product-page');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Error adding product.');
    }
});

app.post('/edit-product/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const { name, description, price, quantity, size, color } = req.body;

        // Find the product in the Payment document and update it
        await Payment.updateOne(
            { "products._id": productId },
            {
                $set: {
                    "products.$.name": name,
                    "products.$.desc": description,
                    "products.$.price": price,
                    "products.$.quantity": quantity,
                    "products.$.size": size,
                    "products.$.color": color,
                }
            }
        );

        req.flash('success_msg', 'Produk telah berjaya dikemas kini.');
        res.redirect('/product-page');
    } catch (err) {
        console.error('Error updating product', err);
        req.flash('error_msg', 'Gagal mengemas kini produk.');
        res.redirect('/product-page');
    }
});

// Route to handle product removal
app.post('/remove-product/:id', async (req, res) => {
    try {
        const productId = req.params.id;

        const result = await Payment.updateOne(
            { isProduct: true },  // Find the payment document with products
            { $pull: { products: { _id: productId } } }  // Remove product by _id
        );

        res.redirect('/product-page');
    } catch (err) {
        console.error('Error deleting product', err);
        res.status(500).send('Error deleting product');
    }
});

app.get('/checkout-summary', async (req, res) => {
    const userId = req.session.user.id;
    const userRole = req.session.user.role;

    if (!userId || !userRole) {
        return res.redirect('/');
    }

    const user = await User.findById(userId);

    if (!user) {
        req.flash('error_msg', 'User not found');
        return res.redirect('/login');
    }

    const { childId, products } = req.query;

    // Fetch the child data
    let child;
    try {
        child = await Child.findById(childId);
        if (!child) {
            return res.status(404).send("Child not found.");
        }
    } catch (err) {
        console.error("Error fetching child:", err);
        return res.status(500).send("Internal Server Error");
    }

    // Calculate the total amount
    let totalAmount = 0;
    let selectedProducts;

    try {
        selectedProducts = JSON.parse(decodeURIComponent(products)).map(product => {
            totalAmount += product.price * product.quantity;
            return product; // Include all details
        });
    } catch (err) {
        console.error("Error parsing products:", err);
        return res.status(400).send("Invalid product data.");
    }

    console.log(selectedProducts);

    // Render the checkout summary page
    res.render('checkout-summary', {
        child,
        products: selectedProducts,
        totalAmount,
        user
    });
});

app.post('/place-order', async (req, res) => {
    try {
        const { childId, totalAmount, product_ids, quantities, product_names, product_prices, product_descriptions, product_colors, product_sizes } = req.body;

        // Ensure product_ids and quantities are always arrays
        const parsedProductIds = Array.isArray(product_ids) ? product_ids : [product_ids];
        const parsedQuantities = Array.isArray(quantities) ? quantities.map(q => Number(q)) : [Number(quantities)];

        const products = [];

        // Loop through product_ids and quantities, and subtract stock if needed
        for (let i = 0; i < parsedProductIds.length; i++) {
            const productId = parsedProductIds[i];
            const quantity = parsedQuantities[i];

            // Find the product by ID in the Payment collection
            const payment = await Payment.findOne({
                "products._id": productId,
                isProduct: true // Ensure you're only finding products
            });

            if (!payment) {
                throw new Error(`Product with ID ${productId} not found or is not a product.`);
            }

            // Find the specific product in the products array
            const product = payment.products.find(product => product._id.toString() === productId);

            if (!product) {
                throw new Error(`Product with ID ${productId} not found in the payment document.`);
            }

            // Check if the product type is 'pakaian', and subtract the stock
            if (product.type === 'pakaian') {
                if (product.quantity < quantity) {
                    throw new Error(`Not enough stock for product: ${product.name}`);
                }

                // Update the stock for the specific product
                await Payment.updateOne(
                    { "products._id": productId },
                    { $inc: { "products.$.quantity": -quantity } } // Subtract the quantity from stock
                );
            }

            // Add product and its ordered quantity to the array with all details
            products.push({
                _id: product._id,
                name: product_names[i],
                price: product_prices[i],
                description: product_descriptions[i],
                color: product_colors[i],
                size: product_sizes[i],
                quantity: quantity
            });
        }

        // Create a new payment record
        const newPayment = new Payment({
            childId: childId,
            products: products, // Use the products array with IDs and quantities
            isProduct: false, // This is for selling display and sell data purposes only
            totalAmount: totalAmount,
            status: 'Pay Now' // Default status upon placing order
        });

        // Save the payment record
        await newPayment.save();

        console.log('Payment placed successfully:', newPayment);

        // Redirect or render a success page
        res.redirect('/'); // Redirect to the dashboard or another page after processing
    } catch (error) {
        console.error('Error placing order:', error.message);
        res.status(500).send('Internal Server Error: ' + error.message);
    }
});

// Route to render the Pay Now page
app.get('/pay-now/:orderid', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }
        const orderid = req.params.orderid;

        // Fetch the invoice details based on the ID
        const invoice = await Payment.findById(orderid)
            .populate('childId', 'name') // Populate the student's name
            .exec();

        if (!invoice) {
            req.flash('error_msg', 'Order not found');
            return res.redirect('/dashboard');
        }

        res.render('pay-now', { invoice, user });
    } catch (err) {
        console.error('Error rendering Pay Now page:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle the receipt upload and payment submission
app.post('/pay-now/:invoiceId', async (req, res) => {
    try {
        const invoiceId = req.params.invoiceId;

        // Ensure the upload directory is defined
        const uploadDir = path.join(__dirname, 'uploads'); // Define your upload directory here

        // Check if a file (receipt) was uploaded
        if (!req.files || Object.keys(req.files).length === 0) {
            req.flash('error_msg', 'No receipt was uploaded');
            return res.redirect(`/pay-now/${invoiceId}`);
        }

        const receipt = req.files.receipt; // Assuming file input is named 'receipt'
        const receiptPath = path.join(uploadDir, receipt.name); // Use receipt.name

        // Save the file to the uploads directory
        receipt.mv(receiptPath, async (err) => {
            if (err) {
                console.error('Error saving receipt:', err);
                req.flash('error_msg', 'Error uploading receipt');
                return res.redirect(`/pay-now/${invoiceId}`);
            }

            // Update the invoice with the receipt file path and set status to 'Pending'
            await Payment.findByIdAndUpdate(invoiceId, {
                File: `/uploads/${receipt.name}`, // Use receipt.name here as well
                status: 'Pending'
            });

            req.flash('success_msg', 'Receipt uploaded successfully. Awaiting approval.');
            res.redirect('/dashboard');
        });
    } catch (err) {
        console.error('Error submitting payment:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Route to show all pending payments for teachers/admins to approve
app.get('/pending-payments', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }
        // Fetch all orders with a 'Pending' status
        const pendingInvoices = await Order.find({ status: 'Pending' })
            .populate('childId', 'name') // Populate the student's name
            .exec();

        res.render('pending-payments', { pendingInvoices, user });
    } catch (err) {
        console.error('Error fetching pending payments:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Route to approve an order
app.post('/approve-order/:orderId', async (req, res) => {
    const { orderId } = req.params;

    try {
        // Find the order and update its status
        const order = await Payment.findById(orderId);
        if (order) {
            order.status = 'Paid';
            await order.save();

            // // Check if the order contains the specified product IDs
            // const productIdsToCheck = [
            //     '66f4b13f6be83cf3d8bc65d3',
            //     '66f4b17a6be83cf3d8bc65ea'
            // ];

            // const containsPaidProduct = order.products.some(product => 
            //     product.productId && productIdsToCheck.includes(product.productId.toString())
            // );

            // if (containsPaidProduct) {
            //     // Insert into BillPayment
            //     const year = order.orderDate.getFullYear(); // Year from the order date
            //     const billPayment = await BillPayment.findOne({ student_id: order.childId, year });

            //     if (billPayment) {
            //         // Update existing bill payment record
            //         billPayment.payments.set('Jan', true); // January
            //         billPayment.payments.set('Nov', true); // November
            //         billPayment.payments.set('Dec', true); // December
            //         await billPayment.save();
            //     } else {
            //         // Create a new bill payment record
            //         const newBillPayment = new BillPayment({
            //             student_id: order.childId,
            //             year: year,
            //             payments: new Map([
            //                 ['Jan', true], // Mark January as paid
            //                 ['Nov', true], // Mark November as paid
            //                 ['Dec', true]  // Mark December as paid
            //             ])
            //         });
            //         await newBillPayment.save();
            //     }
            // }
        }

        res.redirect('/bil-payment-tracker');
    } catch (error) {
        console.error('Error approving order:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to disapprove an order
app.post('/disapprove-order/:orderId', async (req, res) => {
    const { orderId } = req.params;

    // Find the order and update its status
    const order = await Order.findById(orderId);
    if (order) {
        order.status = 'Pending';
        order.paymentApproved = false; // Mark as not approved
        await order.save();
    }

    res.redirect('/bil-payment-tracker');
});

app.post('/withdraw-order/:orderId', async (req, res) => {
    try {
        const orderId = req.params.orderId;

        // Find the order and update it
        await Order.findByIdAndUpdate(orderId, {
            receiptUploaded: false,
            receiptFilePath: null,
            status: 'Withdrawn' // You can set a specific status for withdrawn payments
        });

        req.flash('success_msg', 'Payment withdrawn successfully.');
        res.redirect('/bil-payment-tracker');
    } catch (err) {
        console.error('Error withdrawing payment:', err);
        req.flash('error_msg', 'Error withdrawing payment.');
        res.redirect('/bil-payment-tracker');
    }
});

app.post('/delete-order/:id', async (req, res) => {
    try {
        const orderId = req.params.id;

        // Find and delete the order by ID
        const deletedOrder = await Order.findByIdAndDelete(orderId);

        if (!deletedOrder) {
            req.flash('error_msg', 'Order not found');
            return res.redirect('/bil-payment-tracker');
        }

        req.flash('success_msg', 'Order deleted successfully');
        res.redirect('/bil-payment-tracker');
    } catch (err) {
        console.error('Error deleting order:', err);
        req.flash('error_msg', 'An error occurred while deleting the order');
        res.redirect('/bil-payment-tracker');
    }
});

app.get('/view-receipt/:orderId', async (req, res) => {
    const { orderId } = req.params;
    const order = await Order.findById(orderId);

    if (order) {
        res.render('viewReceipt', { order }); // Create a viewReceipt.ejs to display the receipt
    } else {
        res.status(404).send('Order not found');
    }
});

app.get('/monthly-bil-record', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/');
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }
        let students = [];
        let classes = [];
        let teacherClass = null;
        let selectedClass = req.query.kelas || null;
        const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

        // Fetch all classes for the admin or specific class for teacher
        if (userRole === 'admin') {
            classes = await Class.find({}); // Admin sees all classes
        } else if (userRole === 'teacher') {
            const teacher = await Teacher.findOne({ user_id: userId }).populate('class_id');
            teacherClass = teacher.class_id;
            selectedClass = teacherClass._id;
        }

        // Fetch students based on class filter
        if (selectedClass) {
            students = await Child.find({ class_id: selectedClass }).populate('class_id');
        } else {
            students = await Child.find({}).populate('class_id');
        }

        // Fetch payment records for each student for the year and populate orders
        for (let student of students) {
            student.orders = await Payment.find({
                childId: student._id,
                date: {
                    $gte: new Date(new Date().getFullYear(), 0, 1), // Start of the current year
                    $lt: new Date(new Date().getFullYear() + 1, 0, 1) // End of the current year
                }
            }).exec();
        }

        // Render the EJS page
        res.render('monthly-bil-record2', {
            classes,
            students,
            teacherClass,
            selectedClass,
            user,
            months,
        });
    } catch (err) {
        console.error('Error fetching billing records:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/update-order-status/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const { status } = req.body;

        await Payment.updateOne(
            { '_id': orderId },
            { $set: { 'status': status } },
            { $set: { 'timestamp': Date.now } }
        );

        req.flash('success_msg', 'Order status updated successfully');
        res.redirect('/monthly-bil-record');
    } catch (err) {
        console.error('Error updating order status:', err);
        req.flash('error_msg', 'Failed to update order status');
        res.redirect('/monthly-bil-record');
    }
});

// app.get('/monthly-bil-record', async (req, res) => {
//     try {
//         const userId = req.session.user.id;
//         const userRole = req.session.user.role;

//         if (!userId || !userRole) {
//             return res.redirect('/');
//         }

//         const user = await User.findById(userId);

//         if (!user) {
//             req.flash('error_msg', 'User not found');
//             return res.redirect('/login');
//         }

//         const classes = await Class.find({}).populate('teachersincharge').exec();
//         let students = [];
        
//         const selectedYear = req.query.year || new Date().getFullYear();
//         const selectedClassId = req.query.classId; // Get the selected class ID

//         if (userRole === 'teacher') {
//             const userTeacher = await Teacher.findById(userId).populate('class_id');
//             students = await Child.find({ class_id: userTeacher.class_id }).exec();
//         } else if (userRole === 'admin') {
//             if (selectedClassId) {
//                 students = await Child.find({ class_id: selectedClassId }).exec(); // Filter by selected class for admin
//             } else {
//                 students = await Child.find({}).exec(); // Get all students if no class is selected
//             }
//         } else {
//             students = await Child.find({}).exec(); // For other roles, default behavior
//         }

//         // Clean up Payment records associated with deleted students
//         const studentIds = students.map(student => student._id);
//         await Payment.deleteMany({ childId: { $nin: studentIds } }); // Delete records for non-existing students

//         const payments = await Payment.find({ 
//             childId: { $in: studentIds },
//             'products._id': { $in: ['66f4b13f6be83cf3d8bc65d3', '66f4b17a6be83cf3d8bc65ea'] },
//             status: 'Paid' 
//         }).populate('childId');

//         // Initialize payments for each student
//         students.forEach(student => {
//             const studentPayments = payments.filter(payment => payment.childId._id.equals(student._id));
//             student.payments = {
//                 Jan: false,
//                 Nov: false,
//                 Dec: false,
//                 // You can add other months here if needed
//             };
            
//             // Check for payment status for Jan, Nov, Dec
//             studentPayments.forEach(payment => {
//                 if (payment.products.some(product => product._id.equals('66f4b13f6be83cf3d8bc65d3') || product._id.equals('66f4b17a6be83cf3d8bc65ea'))) {
//                     student.payments.Jan = true; // Assuming January covers this product
//                     student.payments.Nov = true; // Assuming November covers this product
//                     student.payments.Dec = true; // Assuming December covers this product
//                 }
//             });
//         });

//         res.render('monthly-bil-record', { classes, students, user, selectedYear, selectedClassId });
//     } catch (err) {
//         console.error('Error fetching monthly bil record:', err);
//         res.status(500).send('Internal Server Error');
//     }
// });

// POST route for saving monthly billing record
app.post('/monthly-bil-record/save', async (req, res) => {
    try {
        const { classId, payments, year } = req.body; // Capture the year from the request body
        const selectedYear = year || new Date().getFullYear(); // Default to current year if not provided

        for (const studentId in payments) {
            const existingRecord = await BillPayment.findOne({ student_id: studentId, year: selectedYear });

            const paymentData = {};
            for (const month in payments[studentId]) {
                paymentData[month] = payments[studentId][month] === 'true'; // Cast string to Boolean
            }

            if (existingRecord) {
                // Update existing record
                existingRecord.payments = paymentData;
                await existingRecord.save();
            } else {
                // Create new record
                const newRecord = new BillPayment({
                    student_id: studentId,
                    year: selectedYear,
                    payments: paymentData
                });
                await newRecord.save();
            }
        }

        req.flash('success_msg', 'Records saved successfully');
        res.redirect(`/monthly-bil-record?year=${selectedYear}`); // Redirect back with selected year
    } catch (err) {
        console.error('Error saving monthly bil records:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/reset-password', async (req, res) => {
    const teacherId = req.body.teacherId;
    const teacher = await User.findById(teacherId);
    if (!teacher && !teacher.role == 'teacher') {
      return res.status(404).json({ error: 'Teacher not found' });
    }
  
    // Generate a new password  
    // const newPassword = generateRandomPassword();
    const newPassword = "abc123";
  
    // Update the teacher's password
    teacher.password = await bcrypt.hash(newPassword, 10);
    await teacher.save();
  
    // Send a response back to the client
    res.json({ success: true });
});
  
  // Helper function to generate a random password
//   function generateRandomPassword() {
//     const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
//     const passwordLength = 12;
//     let password = '';
//     for (let i = 0; i < passwordLength; i++) {
//       password += characters.charAt(Math.floor(Math.random() * characters.length));
//     }
//     return password;
//   }

// Class list
app.get('/classlist', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const classes = await Class.find({})
            .populate('teachersincharge') // Ensure teachersincharge is populated
            .exec();

        const classList = await Promise.all(classes.map(async cls => {
            const studentCount = await Child.countDocuments({ class_id: cls._id });
            
            // Find the number of students present (HADIR status) for the current date
            const today = new Date();
            today.setHours(0, 0, 0, 0); // Start of the day

            const presentCount = await Attendance.countDocuments({
                student_id: { $in: (await Child.find({ class_id: cls._id }).select('_id')) },
                status: 'HADIR',
                date: today
            });

            return {
                classId: cls._id,
                classname: cls.classname,
                teachersincharge: cls.teachersincharge || [],  // Handle missing teachersincharge
                studentCount,
                studentsPresent: presentCount
            };
        }));

        res.render('classlist', { classList, user });
    } catch (err) {
        console.error('Error fetching class list:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/classdetails/:classId', async (req, res) => {
    try {
        const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        const classId = req.params.classId;

        // Fetch class details and the teachers in charge
        const classDetails = await Class.findById(classId)
            .populate('teachersincharge')
            .exec();

        if (!classDetails) {
            return res.status(404).send('Class not found');
        }

        // Fetch all students in the class
        const students = await Child.find({ class_id: classId })
            .select('name dob gender')
            .exec();

        if (students.length === 0) {
            return res.render('classdetails', {
                classDetails,
                teachers: classDetails.teachersincharge,
                students: [],
                user
            });
        }

        // Fetch today's attendance records for these students
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Set to start of the day

        const studentIds = students.map(student => student._id);
        
        // Get attendance records for the students for today's date
        const attendanceRecords = await Attendance.find({
            student_id: { $in: studentIds },
            date: today
        }).select('student_id status').exec();

        // Map attendance status to each student
        const studentWithAttendance = students.map(student => {
            const attendance = attendanceRecords.find(record => record.student_id.equals(student._id));
            return {
                ...student.toObject(),
                attendanceStatus: attendance ? attendance.status : 'No Record'
            };
        });

        // Render the class details page with students and their attendance
        res.render('classdetails', {
            classDetails,
            teachers: classDetails.teachersincharge,
            students: studentWithAttendance,  // Pass students with their attendance status
            user
        });
    } catch (err) {
        console.error('Error fetching class details:', err);
        res.status(500).send('Internal Server Error');
    }
});

// i-Tary Settings
app.get('/settings', async (req, res) => {
    const userId = req.session.user.id;
        const userRole = req.session.user.role;

        if (!userId || !userRole) {
            return res.redirect('/'); // Redirect to login if not authenticated
        }

        const user = await User.findById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

    if (!user) {
        req.flash('error_msg', 'User not found');
        return res.redirect('/login');
    }

    // Fetch global settings
    settings = await Settings.findOne();

    if (settings) {
        carouselImages = settings.carouselImages;
    }

    res.render('settings', { user, carouselImages });
});

// Handle form submissions for carousel content, account settings, and header color
app.post('/settings/carousel', async (req, res) => {
    // Logic to save carousel image path to the database
});

app.post('/settings/account', async (req, res) => {
    // Logic to update username, email, and password
});

app.post('/settings/header-color', async (req, res) => {
    // Logic to update header color in the database
});

app.post('/upload-carousel', async (req, res) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        console.error('No files were uploaded.', req.files);
        return res.status(400).json({ message: 'No files were uploaded.' });
    }

    const carouselImage = req.files.carouselImage;
    const fileName = `carousel-${Date.now()}${path.extname(carouselImage.name)}`;
    const uploadPath = path.join(uploadDir, fileName);

    try {
        await carouselImage.mv(uploadPath);

        const userId = req.session.user.id;
        console.log('User ID from session:', userId);

        const settings = await Settings.findOne({ user: userId }) || new Settings({ user: userId });

        // Create the new image object
        const newImage = {
            imageUrl: `/uploads/${fileName}`,
            caption: req.body.caption || '',
            description: req.body.description || ''
        };

        // Add the new image object to the carouselImages array
        settings.carouselImages.push(newImage);
        await settings.save();

        res.json({ message: 'Carousel image uploaded successfully.' });
    } catch (error) {
        console.error('Error saving carousel image:', error);
        res.status(500).json({ message: 'Error saving carousel image.' });
    }
});

app.post('/update-carousel', async (req, res) => {
    const userId = req.session.user.id;
    const index = req.body.index; // Get the index of the image to update

    // Get the settings document
    const settings = await Settings.findOne({ user: userId });
    if (!settings) {
        return res.status(404).json({ message: 'Settings not found.' });
    }

    // Update the specified image's caption and description
    if (settings.carouselImages[index]) {
        settings.carouselImages[index].caption = req.body.caption || '';
        settings.carouselImages[index].description = req.body.description || '';

        // If a new image is uploaded, handle the upload logic here...

        await settings.save();
        return res.json({ message: 'Carousel image updated successfully.' });
    } else {
        return res.status(400).json({ message: 'Invalid image index.' });
    }
});

app.post('/delete-carousel/:id', async (req, res) => {
    const id  = req.params.id; // Get the image ID from the request body
    console.log('Image ID:', id);

    if (!id) {
        console.error('Invalid image ID:', id);
        return res.status(400).json({ message: 'Invalid image ID.' });
    }

    const userId = req.session.user.id;

    try {
        const settings = await Settings.findOneAndUpdate(
            { user: userId },
            { $pull: { carouselImages: { _id: id } } },
            { new: true }
        );

        if (settings) {
            // Optionally delete the file from the server
            const imageToDelete = settings.carouselImages.find(img => img._id.toString() === id);
            if (imageToDelete) {
                const filePath = path.join(uploadDir, path.basename(imageToDelete.imageUrl));
                fs.unlink(filePath, (err) => {
                    if (err) console.error('Error deleting file:', err);
                });
            }

            res.redirect('/settings');
        } else {
            return res.status(404).json({ message: 'Settings not found.' });
        }
    } catch (error) {
        console.error('Error deleting carousel image:', error);
        return res.status(500).json({ message: 'Error deleting carousel image.' });
    }
});

app.post('/update-account', async (req, res) => {
    try {
        const { username, email, password, confirmPassword } = req.body;
        const userId = req.session._id; // Get user ID from session

        // Validate passwords if provided
        if (password && password !== confirmPassword) {
            return res.status(400).send('Passwords do not match.');
        }

        // Find the user by ID
        let user = await User.findById(userId);

        // If user not found, check in Parent and Teacher collections
        if (!user) {
            user = await Parent.findById(userId) || await Teacher.findById(userId);
            if (!user) {
                return res.status(404).send('User not found.');
            }
        }

        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser && existingUser._id.toString() !== userId) {
            return res.status(400).send('Email already registered.');
        }

        // Update user details
        user.username = username;
        user.email = email;

        // Update password if provided
        if (password) {
            user.password = await bcrypt.hash(password, 10); // Hash the new password
        }

        await user.save(); // Save the updated user

        res.send('Account updated successfully.'); // You can redirect or send a success message
    } catch (error) {
        console.error('Error updating account:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/update-header-color', async (req, res) => {
  try {
    const headerColor = req.body.headerColor;

    // Use a static ID to always update the same document
    const settingId = '66f626a11f3c4f6ce4669863'; 

    // Find the setting by static ID and update the headerColor field
    await Settings.findOneAndUpdate(
      { _id: settingId },
      { headerColor },
      { new: true, upsert: true } // Upsert to create if it doesn't exist
    );

    res.redirect('/settings'); // Redirect back to your settings page
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Example Express route
app.get('/api/search', async (req, res) => {
    const { query } = req.query;

    if (!query) {
        return res.status(400).json({ error: 'Query parameter is required' });
    }

    try {
        // Assuming you have a list of sidebar items in an array
        const sidebarItems = [
            { name: 'Dashboard', link: '/dashboard' },
            { name: 'Classes', link: '/classlist' },
            { name: 'Students', link: '/table' },
            { name: 'Teachers', link: '/table-guru' },
            { name: 'Product', link: '/product-page' },
            { name: 'Home', link: '/' },
            { name: 'Senarai Kelas', link: '/classlist' },
            { name: 'Senarai Pelajar', link: '/table' },
            { name: 'Senarai Guru', link: '/table-guru' },
            { name: 'Bil pelajar', link: '/bil-payment-tracker' },
        ];

        // Filter sidebar items based on the query
        const suggestions = sidebarItems.filter(item => 
            item.name.toLowerCase().includes(query)
        );

        res.json(suggestions);
    } catch (error) {
        console.error('Error fetching suggestions:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
